// Copyright 2022 The Centipede Authors.
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

// The Centipede seed corpus maker. Following the input text proto config in the
// ./seed_corpus_config.proto format, selects a sample of fuzzing inputs from N
// Centipede workdirs and writes them out to a new set of Centipede corpus file
// shards.

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <functional>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/random/random.h"
#include "absl/strings/match.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_replace.h"
#include "absl/time/time.h"
#include "./centipede/blob_file.h"
#include "./centipede/defs.h"
#include "./centipede/feature.h"
#include "./centipede/logging.h"
#include "./centipede/remote_file.h"
#include "./centipede/rusage_profiler.h"
#include "./centipede/seed_corpus_config.pb.h"
#include "./centipede/shard_reader.h"
#include "./centipede/thread_pool.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"
#include "google/protobuf/text_format.h"

// TODO(ussuri): Add unit tests.
// TODO(ussuri): Implement a smarter on-the-fly sampling to avoid having to
//  load all of a source's elements into RAM only to pick some of them. That
//  would be trivial if the number of elements in a corpus file could be
//  determined without reading all of it.
// TODO(ussuri): Switch from hard CHECKs to returning absl::Status once
//  convenience macros are available (RETURN_IF_ERROR etc.).

namespace centipede {

namespace fs = std::filesystem;

using InputAndFeatures = std::pair<ByteArray, FeatureVec>;
using InputAndFeaturesVec = std::vector<InputAndFeatures>;

SeedCorpusConfig ResolveSeedCorpusConfig(  //
    std::string_view config_spec,          //
    std::string_view override_out_dir) {
  std::string config_str;
  std::string base_dir;

  CHECK(!config_spec.empty());

  if (RemotePathExists(config_spec)) {
    LOG(INFO) << "Config spec points at an existing file; trying to parse "
                 "textproto config from it: "
              << VV(config_spec);
    RemoteFileGetContents(config_spec, config_str);
    LOG(INFO) << "Raw config read from file:\n" << config_str;
    base_dir = std::filesystem::path{config_spec}.parent_path();
  } else {
    LOG(INFO) << "Config spec is not a file, or file doesn't exist; trying to "
                 "parse textproto config verbatim: "
              << VV(config_spec);
    config_str = config_spec;
    base_dir = fs::current_path();
  }

  SeedCorpusConfig config;
  CHECK(google::protobuf::TextFormat::ParseFromString(config_str, &config))
      << "Couldn't parse config: " << VV(config_str);
  CHECK_EQ(config.sources_size() > 0, config.has_destination())
      << "Non-empty config must have both source(s) and destination: "
      << VV(config_spec) << VV(config.DebugString());

  LOG(INFO) << "Parsed config:\n" << config.DebugString();

  // Resolve relative `source.dir_glob`s in the config to absolute ones.
  for (auto& src : *config.mutable_sources()) {
    auto* dir = src.mutable_dir_glob();
    if (dir->empty() || !fs::path{*dir}.is_absolute()) {
      *dir = fs::path{base_dir} / *dir;
    }
  }

  // Set `destination.dir_path` to `override_out_dir`, if the latter is
  // non-empty, or resolve a relative `destination.dir_path` to an absolute one.
  if (config.has_destination()) {
    auto* dir = config.mutable_destination()->mutable_dir_path();
    if (!override_out_dir.empty()) {
      *dir = override_out_dir;
    } else if (dir->empty() || !fs::path{*dir}.is_absolute()) {
      *dir = fs::path{base_dir} / *dir;
    }
  }

  if (config.destination().shard_index_digits() == 0) {
    config.mutable_destination()->set_shard_index_digits(
        WorkDir::kDigitsInShardIndex);
  }

  LOG(INFO) << "Resolved config:\n" << config.DebugString();

  return config;
}

// TODO(ussuri): Refactor into smaller functions.
void SampleSeedCorpusElementsFromSource(    //
    const SeedCorpusSource& source,         //
    std::string_view coverage_binary_name,  //
    std::string_view coverage_binary_hash,  //
    InputAndFeaturesVec& elements) {
  RPROF_THIS_FUNCTION_WITH_TIMELAPSE(                                 //
      /*enable=*/true,                                                //
      /*timelapse_interval=*/absl::Seconds(VLOG_IS_ON(1) ? 10 : 60),  //
      /*also_log_timelapses=*/VLOG_IS_ON(10));

  LOG(INFO) << "Reading/sampling seed corpus elements from source:\n"
            << source.DebugString();

  // Find `source.dir_glob()`-matching dirs and pick at most
  // `source.num_recent_dirs()` most recent ones.

  std::vector<std::string> src_dirs;
  RemoteGlobMatch(source.dir_glob(), src_dirs);
  LOG(INFO) << "Found " << src_dirs.size() << " corpus dirs matching "
            << source.dir_glob();
  // Sort in the ascending lexicographical order. We expect that dir names
  // contain timestamps and therefore will be sorted from oldest to newest.
  std::sort(src_dirs.begin(), src_dirs.end(), std::less<std::string>());
  if (source.num_recent_dirs() < src_dirs.size()) {
    src_dirs.erase(src_dirs.begin(), src_dirs.end() - source.num_recent_dirs());
    LOG(INFO) << "Selected " << src_dirs.size() << " corpus dirs";
  }

  // Find all the corpus shard files in the found dirs.

  std::vector<std::string> corpus_shard_fnames;
  for (const auto& dir : src_dirs) {
    const std::string shards_glob = fs::path{dir} / source.shard_rel_glob();
    // NOTE: `RemoteGlobMatch` appends to the output list.
    const auto prev_num_shards = corpus_shard_fnames.size();
    RemoteGlobMatch(shards_glob, corpus_shard_fnames);
    LOG(INFO) << "Found " << (corpus_shard_fnames.size() - prev_num_shards)
              << " shards matching " << shards_glob;
  }
  LOG(INFO) << "Found " << corpus_shard_fnames.size()
            << " shards total in source " << source.dir_glob();

  if (corpus_shard_fnames.empty()) {
    LOG(WARNING) << "Skipping empty source " << source.dir_glob();
    return;
  }

  // Read all the elements from the found corpus shard files using parallel I/O
  // threads.

  const auto num_shards = corpus_shard_fnames.size();
  std::vector<InputAndFeaturesVec> src_elts_per_shard(num_shards);
  std::vector<size_t> src_num_features_per_shard(num_shards, 0);

  {
    constexpr int kMaxReadThreads = 32;
    ThreadPool threads{std::min<int>(kMaxReadThreads, num_shards)};

    for (int shard = 0; shard < num_shards; ++shard) {
      const auto& corpus_fname = corpus_shard_fnames[shard];
      auto& shard_elts = src_elts_per_shard[shard];
      auto& shard_num_features = src_num_features_per_shard[shard];

      const auto read_shard = [shard, corpus_fname, coverage_binary_name,
                               coverage_binary_hash, &shard_elts,
                               &shard_num_features]() {
        // NOTE: The deduced matching `features_fname` may not exist if the
        // source corpus was generated for a coverage binary that is different
        // from the one we need, but `ReadShard()` can tolerate that, passing
        // empty `FeatureVec`s to the callback if that's the case.
        const auto work_dir = WorkDir::FromCorpusShardPath(  //
            corpus_fname, coverage_binary_name, coverage_binary_hash);
        const std::string features_fname =
            work_dir.CorpusFiles().IsShardPath(corpus_fname)
                ? work_dir.FeaturesFiles().MyShardPath()
            : work_dir.DistilledCorpusFiles().IsShardPath(corpus_fname)
                ? work_dir.DistilledFeaturesFiles().MyShardPath()
                : "";

        LOG(INFO) << "Reading elements from source shard " << shard << ":\n"
                  << VV(corpus_fname) << "\n"
                  << VV(features_fname);

        size_t prev_shard_elts_size = shard_elts.size();
        size_t prev_shard_num_features = shard_num_features;

        ReadShard(corpus_fname, features_fname,
                  [&shard_elts, &shard_num_features](  //
                      const ByteArray& input, FeatureVec& features) {
                    shard_num_features += features.empty() ? 0 : 1;
                    shard_elts.emplace_back(input, std::move(features));
                  });

        LOG(INFO) << "Read " << (shard_elts.size() - prev_shard_elts_size)
                  << " elements ("
                  << (shard_num_features - prev_shard_num_features)
                  << " with features) from source shard " << shard;
      };

      threads.Schedule(read_shard);
    }
  }

  InputAndFeaturesVec src_elts;
  size_t src_num_features = 0;

  for (int s = 0; s < num_shards; ++s) {
    auto& shard_elts = src_elts_per_shard[s];
    for (auto& elt : shard_elts) {
      src_elts.emplace_back(std::move(elt));
    }
    shard_elts.clear();
    src_num_features += src_num_features_per_shard[s];
  }

  src_elts_per_shard.clear();
  src_num_features_per_shard.clear();

  RPROF_SNAPSHOT_AND_LOG("Done reading");

  LOG(INFO) << "Read total of " << src_elts.size() << " elements ("
            << src_num_features << " with features) from source "
            << source.dir_glob();

  // Extract a sample of the elements of the size specified in
  // `source.sample_size()`.

  size_t sample_size = 0;
  switch (source.sample_size_case()) {
    case SeedCorpusSource::kSampledFraction:
      CHECK(source.sampled_fraction() > 0.0 && source.sampled_fraction() <= 1.0)
          << VV(source.DebugString());
      sample_size = std::llrint(src_elts.size() * source.sampled_fraction());
      break;
    case SeedCorpusSource::kSampledCount:
      sample_size = std::min<size_t>(src_elts.size(), source.sampled_count());
      break;
    case SeedCorpusSource::SAMPLE_SIZE_NOT_SET:
      sample_size = src_elts.size();
      break;
  }

  if (sample_size < src_elts.size()) {
    LOG(INFO) << "Sampling " << sample_size << " elements out of "
              << src_elts.size();
    std::sample(  //
        src_elts.cbegin(), src_elts.cend(), std::back_inserter(elements),
        sample_size, absl::BitGen{});
  } else {
    LOG(INFO) << "Using all " << src_elts.size() << " elements";
    // TODO(ussuri): Should we still use std::sample() to randomize the order?
    elements.insert(elements.end(), src_elts.cbegin(), src_elts.cend());
  }

  RPROF_SNAPSHOT_AND_LOG("Done sampling");
}

// TODO(ussuri): Refactor into smaller functions.
void WriteSeedCorpusElementsToDestination(  //
    const InputAndFeaturesVec& elements,    //
    std::string_view coverage_binary_name,  //
    std::string_view coverage_binary_hash,  //
    const SeedCorpusDestination& destination) {
  RPROF_THIS_FUNCTION_WITH_TIMELAPSE(                                 //
      /*enable=*/true,                                                //
      /*timelapse_interval=*/absl::Seconds(VLOG_IS_ON(1) ? 10 : 60),  //
      /*also_log_timelapses=*/VLOG_IS_ON(10));

  LOG(INFO) << "Writing seed corpus elements to destination:\n"
            << destination.DebugString();

  CHECK_GT(destination.num_shards(), 0)
      << "Requested number of shards can't be 0";
  CHECK(absl::StrContains(destination.shard_rel_glob(), "*"))
      << "Shard pattern must contain '*' placeholder for shard index";

  // Compute shard sizes. If the elements can't be evenly divided between the
  // requested number of shards, distribute the N excess elements between the
  // first N shards.
  const size_t num_shards =
      std::min<size_t>(destination.num_shards(), elements.size());
  const size_t shard_size = elements.size() / num_shards;
  std::vector<size_t> shard_sizes(num_shards, shard_size);
  const size_t excess_elts = elements.size() % num_shards;
  for (size_t i = 0; i < excess_elts; ++i) {
    ++shard_sizes[i];
  }

  // Write the elements to the shard files using parallel I/O threads.
  {
    constexpr int kMaxWriteThreads = 1000;
    ThreadPool threads{std::min<int>(kMaxWriteThreads, num_shards)};

    auto shard_elt_it = elements.cbegin();

    for (size_t shard = 0; shard < shard_sizes.size(); ++shard) {
      // Compute this shard's range of the input elements to write.
      const auto shard_size = shard_sizes[shard];
      const auto elt_range_begin = shard_elt_it;
      std::advance(shard_elt_it, shard_size);
      const auto elt_range_end = shard_elt_it;
      CHECK(shard_elt_it <= elements.cend()) << VV(shard);

      const auto write_shard = [shard, elt_range_begin, elt_range_end,
                                coverage_binary_name, coverage_binary_hash,
                                &destination]() {
        // Generate the output shard's filename.
        // TODO(ussuri): Use more of `WorkDir` APIs here (possibly extend
        // them, and possibly retire
        // `SeedCorpusDestination::shard_index_digits`).
        const std::string shard_idx =
            absl::StrFormat("%0*d", destination.shard_index_digits(), shard);
        const std::string corpus_rel_fname = absl::StrReplaceAll(
            destination.shard_rel_glob(), {{"*", shard_idx}});
        const std::string corpus_fname =
            fs::path{destination.dir_path()} / corpus_rel_fname;

        const auto work_dir = WorkDir::FromCorpusShardPath(  //
            corpus_fname, coverage_binary_name, coverage_binary_hash);

        CHECK(corpus_fname == work_dir.CorpusFiles().MyShardPath() ||
              corpus_fname == work_dir.DistilledCorpusFiles().MyShardPath())
            << "Bad config: generated destination corpus filename '"
            << corpus_fname << "' doesn't match one of two expected forms '"
            << work_dir.CorpusFiles().MyShardPath() << "' or '"
            << work_dir.DistilledCorpusFiles().MyShardPath()
            << "'; make sure binary name in config matches explicitly passed '"
            << coverage_binary_name << "'";

        const std::string features_fname =
            work_dir.CorpusFiles().IsShardPath(corpus_fname)
                ? work_dir.FeaturesFiles().MyShardPath()
                : work_dir.DistilledFeaturesFiles().MyShardPath();
        CHECK(!features_fname.empty());

        LOG(INFO) << "Writing " << std::distance(elt_range_begin, elt_range_end)
                  << " elements to destination shard " << shard << ":\n"
                  << VV(corpus_fname) << "\n"
                  << VV(features_fname);

        // Features files are always saved in a subdir of the workdir
        // (== `destination.dir_path()` here), which might not exist yet, so we
        // create it. Corpus files are saved in the workdir directly, but we
        // also create it in case `destination.shard_rel_glob()` contains some
        // dirs (not really intended for that, but the end-user may do that).
        for (const auto& fname : {corpus_fname, features_fname}) {
          if (!fname.empty()) {
            const auto dir = fs::path{fname}.parent_path().string();
            if (!RemotePathExists(dir)) RemoteMkdir(dir);
          }
        }

        // Create writers for the corpus and features shard files.

        // TODO(ussuri): 1. Once the whole thing is a class, make
        // `num_non_empty_features` a member and don't even create a features
        // file if 0. 2. Wrap corpus/features writing in a similar API to
        // `ReadShard()`.

        const std::unique_ptr<centipede::BlobFileWriter> corpus_writer =
            centipede::DefaultBlobFileWriterFactory();
        CHECK(corpus_writer != nullptr);
        CHECK_OK(corpus_writer->Open(corpus_fname, "w")) << VV(corpus_fname);

        const std::unique_ptr<centipede::BlobFileWriter> features_writer =
            DefaultBlobFileWriterFactory();
        CHECK(features_writer != nullptr);
        CHECK_OK(features_writer->Open(features_fname, "w"))
            << VV(features_fname);

        // Write the shard's elements to the corpus and features shard files.

        for (auto elt_it = elt_range_begin; elt_it != elt_range_end; ++elt_it) {
          const ByteArray& input = elt_it->first;
          CHECK_OK(corpus_writer->Write(input)) << VV(corpus_fname);
          const FeatureVec& features = elt_it->second;
          if (!features.empty()) {
            const ByteArray packed_features =
                PackFeaturesAndHash(input, features);
            CHECK_OK(features_writer->Write(packed_features))
                << VV(features_fname);
          }
        }

        LOG(INFO) << "Wrote " << std::distance(elt_range_begin, elt_range_end)
                  << " elements to destination shard " << shard;

        CHECK_OK(corpus_writer->Close()) << VV(corpus_fname);
        CHECK_OK(features_writer->Close()) << VV(features_fname);
      };

      threads.Schedule(write_shard);
    }
  }
}

void GenerateSeedCorpusFromConfig(          //
    std::string_view config_spec,           //
    std::string_view coverage_binary_name,  //
    std::string_view coverage_binary_hash,  //
    std::string_view override_out_dir) {
  const SeedCorpusConfig config =
      ResolveSeedCorpusConfig(config_spec, override_out_dir);

  if (config.sources_size() == 0 || !config.has_destination()) {
    LOG(WARNING) << "Config is empty: skipping seed corpus generation";
    return;
  }

  // Pre-create the destination dir early to catch possible misspellings etc.
  if (!RemotePathExists(config.destination().dir_path())) {
    RemoteMkdir(config.destination().dir_path());
  }

  InputAndFeaturesVec elements;

  for (const auto& source : config.sources()) {
    SampleSeedCorpusElementsFromSource(  //
        source, coverage_binary_name, coverage_binary_hash, elements);
  }
  LOG(INFO) << "Sampled " << elements.size() << " elements from "
            << config.sources_size() << " seed corpus source(s)";

  WriteSeedCorpusElementsToDestination(  //
      elements, coverage_binary_name, coverage_binary_hash,
      config.destination());
  LOG(INFO) << "Wrote " << elements.size()
            << " elements to seed corpus destination";
}

}  // namespace centipede
