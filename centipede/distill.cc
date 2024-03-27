// Copyright 2023 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./centipede/distill.h"

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <functional>
#include <memory>
#include <numeric>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "./centipede/blob_file.h"
#include "./centipede/corpus_io.h"
#include "./centipede/defs.h"
#include "./centipede/environment.h"
#include "./centipede/feature.h"
#include "./centipede/feature_set.h"
#include "./centipede/logging.h"
#include "./centipede/remote_file.h"
#include "./centipede/resource_pool.h"
#include "./centipede/rusage_profiler.h"
#include "./centipede/rusage_stats.h"
#include "./centipede/thread_pool.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"

namespace centipede {

namespace {

struct CorpusElt {
  ByteArray input;
  FeatureVec features;

  CorpusElt(const ByteArray &input, FeatureVec features)
      : input(input), features(std::move(features)) {}

  // Movable, but not copyable for efficiency.
  CorpusElt(const CorpusElt &) = delete;
  CorpusElt &operator=(const CorpusElt &) = delete;
  CorpusElt(CorpusElt &&) = default;
  CorpusElt &operator=(CorpusElt &&) = default;

  ByteArray PackedFeatures() const {
    return PackFeaturesAndHash(input, features);
  }
};

using CorpusEltVec = std::vector<CorpusElt>;

// The maximum number of threads reading input shards concurrently. This is
// mainly to prevent I/O congestion.
inline constexpr size_t kMaxReadingThreads = 100;
// The maximum number of threads writing shards concurrently. These in turn
// launch up to `kMaxReadingThreads` reading threads.
inline constexpr size_t kMaxWritingThreads = 10;
// A global cap on the total number of threads, both writing and reading. Unlike
// the other two limits, this one is purely to prevent too many threads in the
// process.
inline constexpr size_t kMaxTotalThreads = 1000;
static_assert(kMaxReadingThreads * kMaxWritingThreads <= kMaxTotalThreads);

inline constexpr perf::MemSize kGB = 1024L * 1024L * 1024L;
// The total approximate amount of RAM to be shared by the concurrent threads.
// TODO(ussuri): Replace by a function of free RSS on the system.
inline constexpr perf::RUsageMemory kRamQuota{.mem_rss = 25 * kGB};
// The amount of time that each thread will wait for enough RAM to be freed up
// by its concurrent siblings.
inline constexpr absl::Duration kRamLeaseTimeout = absl::Hours(5);

std::string LogPrefix(const Environment &env) {
  return absl::StrCat("DISTILL[S.", env.my_shard_index, "]: ");
}

// TODO(ussuri): Move the reader/writer classes to shard_reader.cc, rename it
//  to corpus_io.cc, and reuse the new APIs where useful in the code base.

// A helper class for reading input corpus shards. Thread-safe.
class InputCorpusShardReader {
 public:
  InputCorpusShardReader(const Environment &env)
      : workdir_{env}, log_prefix_{LogPrefix(env)} {}

  perf::MemSize EstimateRamFootprint(size_t shard_idx) const {
    const auto corpus_path = workdir_.CorpusFiles().ShardPath(shard_idx);
    const auto features_path = workdir_.FeaturesFiles().ShardPath(shard_idx);
    const perf::MemSize corpus_file_size = RemoteFileGetSize(corpus_path);
    const perf::MemSize features_file_size = RemoteFileGetSize(features_path);
    // Conservative compression factors for the two file types. These have been
    // observed empirically for the Riegeli blob format. The legacy format is
    // approximately 1:1, but use the stricter Riegeli numbers, as the legacy
    // should be considered obsolete.
    // TODO(b/322880269): Use the actual in-memory footprint once available.
    constexpr double kMaxCorpusCompressionRatio = 5.0;
    constexpr double kMaxFeaturesCompressionRatio = 10.0;
    return corpus_file_size * kMaxCorpusCompressionRatio +
           features_file_size * kMaxFeaturesCompressionRatio;
  }

  // Reads and returns a single shard's elements. Thread-safe.
  CorpusEltVec ReadShard(size_t shard_idx) {
    const auto corpus_path = workdir_.CorpusFiles().ShardPath(shard_idx);
    const auto features_path = workdir_.FeaturesFiles().ShardPath(shard_idx);
    VLOG(1) << log_prefix_ << "reading input shard " << shard_idx << ":\n"
            << VV(corpus_path) << "\n"
            << VV(features_path);
    CorpusEltVec elts;
    absl::flat_hash_set<std::string> input_hashes;
    // Read elements from the current shard.
    centipede::ReadShard(  //
        corpus_path, features_path,
        [&elts, &input_hashes](ByteArray input, FeatureVec features) {
          const std::string hash = Hash(input);
          if (input_hashes.contains(hash)) return;
          input_hashes.insert(hash);
          elts.emplace_back(std::move(input), std::move(features));
        });
    return elts;
  }

 private:
  const WorkDir workdir_;
  const std::string log_prefix_;
};

// A helper class for writing corpus shards. Thread-safe.
class CorpusShardWriter {
 public:
  // The writing stats so far.
  struct Stats {
    size_t num_total_elts = 0;
    size_t num_written_elts = 0;
    size_t num_written_batches = 0;
  };

  CorpusShardWriter(const Environment &env, bool append)
      : workdir_{env},
        log_prefix_{LogPrefix(env)},
        corpus_path_{workdir_.DistilledCorpusFiles().MyShardPath()},
        features_path_{workdir_.DistilledFeaturesFiles().MyShardPath()},
        corpus_writer_{DefaultBlobFileWriterFactory()},
        feature_writer_{DefaultBlobFileWriterFactory()} {
    CHECK_OK(corpus_writer_->Open(corpus_path_, append ? "a" : "w"));
    CHECK_OK(feature_writer_->Open(features_path_, append ? "a" : "w"));
  }

  virtual ~CorpusShardWriter() = default;

  void WriteElt(CorpusElt elt) {
    absl::MutexLock lock(&mu_);
    WriteEltImpl(std::move(elt));
  }

  void WriteBatch(CorpusEltVec elts) {
    absl::MutexLock lock(&mu_);
    VLOG(1) << log_prefix_ << "writing " << elts.size()
            << " elements to output shard:\n"
            << VV(corpus_path_) << "\n"
            << VV(features_path_);
    for (auto &elt : elts) {
      WriteEltImpl(std::move(elt));
    }
    ++stats_.num_written_batches;
  }

  Stats GetStats() const {
    absl::MutexLock lock(&mu_);
    return stats_;
  }

 protected:
  // A behavior customization point: a derived class gets an opportunity to
  // analyze and/or preprocess `elt` before it is written. For example, a
  // derived class can trim the element's feature set before it is written, or
  // choose to skip writing it entirely by returning `std::nullopt`.
  virtual std::optional<CorpusElt> PreprocessElt(CorpusElt elt) {
    return std::move(elt);
  }

 private:
  void WriteEltImpl(CorpusElt elt) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_) {
    ++stats_.num_total_elts;
    const auto preprocessed_elt = PreprocessElt(std::move(elt));
    if (preprocessed_elt.has_value()) {
      // Append to the distilled corpus and features files.
      CHECK_OK(corpus_writer_->Write(preprocessed_elt->input));
      CHECK_OK(feature_writer_->Write(preprocessed_elt->PackedFeatures()));
      ++stats_.num_written_elts;
    }
  }

  // Const state.
  const WorkDir workdir_;
  const std::string log_prefix_;
  const std::string corpus_path_;
  const std::string features_path_;

  // Mutable state.
  mutable absl::Mutex mu_;
  std::unique_ptr<BlobFileWriter> corpus_writer_ ABSL_GUARDED_BY(mu_);
  std::unique_ptr<BlobFileWriter> feature_writer_ ABSL_GUARDED_BY(mu_);
  Stats stats_ ABSL_GUARDED_BY(mu_);
};

// A helper class for writing distilled corpus shards. NOT thread-safe because
// all writes go to a single file.
class DistilledCorpusShardWriter : public CorpusShardWriter {
 public:
  // An extension to the parent class's `Stats`.
  struct DistilledStats {
    // The accumulated features of the distilled corpus so far, represents in
    // the same compact textual form that Centipede uses in its fuzzing progress
    // log messages, e.g.: "ft: 96331 cov: 81793 usr1: 5045 ...".
    std::string coverage_str;
  };

  DistilledCorpusShardWriter(const Environment &env, bool append)
      : CorpusShardWriter{env, append},
        feature_set_{/*frequency_threshold=*/1, env.MakeDomainDiscardMask()} {}

  ~DistilledCorpusShardWriter() override = default;

  DistilledStats GetDistilledStats() const {
    absl::MutexLock lock(&mu_);
    DistilledStats stats;
    std::stringstream coverage_ss;
    coverage_ss << feature_set_;
    stats.coverage_str = coverage_ss.str();
    return stats;
  }

 protected:
  std::optional<CorpusElt> PreprocessElt(CorpusElt elt) override {
    absl::MutexLock lock(&mu_);
    feature_set_.PruneDiscardedDomains(elt.features);
    if (!feature_set_.HasUnseenFeatures(elt.features)) return std::nullopt;
    feature_set_.IncrementFrequencies(elt.features);
    return std::move(elt);
  }

 private:
  mutable absl::Mutex mu_;
  FeatureSet feature_set_ ABSL_GUARDED_BY(mu_);
};

}  // namespace

void DistillTask(const Environment &env,
                 const std::vector<size_t> &shard_indices,
                 perf::ResourcePool<perf::RUsageMemory> &ram_pool,
                 int parallelism) {
  // Read and write the shards in parallel, but gate reading of each on the
  // availability of free RAM to keep the peak RAM usage under control.
  const size_t num_shards = shard_indices.size();
  InputCorpusShardReader reader{env};
  // NOTE: Always overwrite corpus and features files, never append.
  DistilledCorpusShardWriter writer{env, /*append=*/false};

  {
    ThreadPool threads{parallelism};
    for (size_t shard_idx : shard_indices) {
      threads.Schedule([shard_idx, &reader, &writer, &env, num_shards,
                        &ram_pool] {
        const auto ram_lease = ram_pool.AcquireLeaseBlocking({
            .id = absl::StrCat("out_", env.my_shard_index, "/in_", shard_idx),
            .amount = {.mem_rss = reader.EstimateRamFootprint(shard_idx)},
            .timeout = kRamLeaseTimeout,
        });
        CHECK_OK(ram_lease.status());

        CorpusEltVec shard_elts = reader.ReadShard(shard_idx);
        // Reverse the order of elements. The intuition is as follows:
        // * If the shard is the result of fuzzing with Centipede, the inputs
        //   that are closer to the end are more interesting, so we start there.
        // * If the shard resulted from somethening else, the reverse order is
        //   not any better or worse than any other order.
        std::reverse(shard_elts.begin(), shard_elts.end());
        writer.WriteBatch(std::move(shard_elts));
        const auto stats = writer.GetStats();
        const auto distilled_stats = writer.GetDistilledStats();
        LOG(INFO) << LogPrefix(env) << distilled_stats.coverage_str
                  << " batches: " << stats.num_written_batches << "/"
                  << num_shards << " inputs: " << stats.num_total_elts
                  << " distilled: " << stats.num_written_elts;
      });
    }
  }  // The reading threads join here.
}

int Distill(const Environment &env) {
  RPROF_THIS_FUNCTION_WITH_TIMELAPSE(                                      //
      /*enable=*/ABSL_VLOG_IS_ON(1),                                       //
      /*timelapse_interval=*/absl::Seconds(ABSL_VLOG_IS_ON(2) ? 10 : 60),  //
      /*also_log_timelapses=*/ABSL_VLOG_IS_ON(10));

  // The RAM pool shared between all the threads, here and in `DistillTask`.
  perf::ResourcePool ram_pool{kRamQuota};

  std::vector<Environment> envs_per_thread(env.num_threads, env);
  std::vector<std::vector<size_t>> shard_indices_per_thread(env.num_threads);
  // Prepare per-thread envs and input shard indices.
  for (size_t thread_idx = 0; thread_idx < env.num_threads; ++thread_idx) {
    envs_per_thread[thread_idx].my_shard_index += thread_idx;
    // Shuffle the shards, so that every thread produces different result.
    Rng rng(GetRandomSeed(env.seed + thread_idx));
    auto &shard_indices = shard_indices_per_thread[thread_idx];
    shard_indices.resize(env.total_shards);
    std::iota(shard_indices.begin(), shard_indices.end(), 0);
    std::shuffle(shard_indices.begin(), shard_indices.end(), rng);
  }

  // Run the distillation threads in parallel.
  {
    const size_t num_threads = std::min(env.num_threads, kMaxWritingThreads);
    ThreadPool threads{static_cast<int>(num_threads)};
    for (size_t thread_idx = 0; thread_idx < env.num_threads; ++thread_idx) {
      threads.Schedule(
          [&thread_env = envs_per_thread[thread_idx],
           &thread_shard_indices = shard_indices_per_thread[thread_idx],
           &ram_pool]() {
            DistillTask(  //
                thread_env, thread_shard_indices, ram_pool, kMaxReadingThreads);
          });
    }
  }  // The writing threads join here.

  return EXIT_SUCCESS;
}

}  // namespace centipede
