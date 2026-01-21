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

#include "./centipede/corpus.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/substitute.h"
#include "./centipede/control_flow.h"
#include "./centipede/coverage.h"
#include "./centipede/execution_metadata.h"
#include "./centipede/feature.h"
#include "./centipede/feature_set.h"
#include "./centipede/runner_result.h"
#include "./centipede/util.h"
#include "./common/defs.h"
#include "./common/logging.h"  // IWYU pragma: keep
#include "./common/remote_file.h"
#include "./common/status_macros.h"

namespace fuzztest::internal {

//------------------------------------------------------------------------------
//                                  Corpus
//------------------------------------------------------------------------------

// Computes the weight component of input using its features `fv` and
// the overall `coverage_frontier`.
static size_t ComputeFrontierWeight(const FeatureVec& fv,
                                    const CoverageFrontier& coverage_frontier) {
  // The following is checking for the cases where PCTable is not present. In
  // such cases, we cannot use any ControlFlow related features.
  if (coverage_frontier.MaxPcIndex() == 0) return 1;
  size_t frontier_weights_sum = 0;
  for (const auto feature : fv) {
    if (!feature_domains::kPCs.Contains(feature)) continue;
    const auto pc_index = ConvertPCFeatureToPcIndex(feature);
    // Avoid checking frontier for out-of-bounds indices.
    // TODO(b/299624088): revisit once dlopen is supported.
    if (pc_index >= coverage_frontier.MaxPcIndex()) continue;
    if (coverage_frontier.PcIndexIsFrontier(pc_index)) {
      frontier_weights_sum += coverage_frontier.FrontierWeight(pc_index);
    }
  }
  return frontier_weights_sum + 1;  // Multiply by at least 1.
}

std::optional<Corpus::WeightMethod> Corpus::ParseWeightMethod(
    std::string_view method_string) {
  if (method_string == "uniform") {
    return WeightMethod::Uniform;
  } else if (method_string == "recency") {
    return WeightMethod::Recency;
  } else if (method_string == "feature_rarity") {
    return WeightMethod::FeatureRarity;
  }
  return std::nullopt;
}

std::pair<size_t, size_t> Corpus::MaxAndAvgSize() const {
  if (records_.empty()) return {0, 0};
  size_t max = 0;
  size_t total = 0;
  for (const auto &r : records_) {
    max = std::max(max, r.data.size());
    total += r.data.size();
  }
  return {max, total / records_.size()};
}

void Corpus::UpdateWeights(const FeatureSet& fs,
                           const CoverageFrontier& coverage_frontier,
                           bool scale_by_exec_time) {
  std::vector<double> weights;
  weights.resize(records_.size());
  for (size_t i = 0, n = records_.size(); i < n; ++i) {
    auto& record = records_[i];
    const size_t unseen = fs.PruneFeaturesAndCountUnseen(record.features);
    FUZZTEST_CHECK_EQ(unseen, 0);
    if (record.features.empty()) {
      weights[i] = 0;
      continue;
    }
    double base_weight = 0;
    switch (method_) {
      case WeightMethod::Uniform:
        base_weight = 1;
        break;
      case WeightMethod::Recency:
        base_weight = i + 1;
        break;
      case WeightMethod::FeatureRarity:
        base_weight = fs.ComputeRarityWeight(record.features);
        break;
      default:
        FUZZTEST_LOG(FATAL) << "Unknown corpus weight method";
    }
    weights[i] =
        base_weight * ComputeFrontierWeight(record.features, coverage_frontier);
  }
  if (scale_by_exec_time) {
    double total_exec_time_usec = 0;
    // For loaded corpus, we don't have the exec time recorded. Thus we don't
    // count them when calculating the average exec time or scale their weights.
    size_t exec_time_divider = 0;
    for (const auto& record : records_) {
      if (!(record.stats == ExecutionResult::Stats{})) {
        total_exec_time_usec += record.stats.exec_time_usec;
        ++exec_time_divider;
      }
    }
    const double avg_exec_time_usec =
        exec_time_divider == 0 ? 0 : total_exec_time_usec / exec_time_divider;
    for (size_t i = 0; i < records_.size(); ++i) {
      const auto& record = records_[i];
      if (record.stats == ExecutionResult::Stats{}) {
        continue;
      }
      // Same as the scaling method from libFuzzer:
      // https://github.com/llvm/llvm-project/blob/10bec2cd9dab796d5685fa8aadf47b912e3558fe/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L101
      if (record.stats.exec_time_usec > avg_exec_time_usec * 10) {
        weights[i] *= 0.1;
      } else if (record.stats.exec_time_usec > avg_exec_time_usec * 4) {
        weights[i] *= 0.25;
      } else if (record.stats.exec_time_usec > avg_exec_time_usec * 2) {
        weights[i] *= 0.5;
      } else if (record.stats.exec_time_usec * 3 > avg_exec_time_usec * 4) {
        weights[i] *= 0.75;
      } else if (record.stats.exec_time_usec * 4 < avg_exec_time_usec) {
        weights[i] *= 3;
      } else if (record.stats.exec_time_usec * 3 < avg_exec_time_usec) {
        weights[i] *= 2;
      } else if (record.stats.exec_time_usec * 2 < avg_exec_time_usec) {
        weights[i] *= 1.5;
      }
    }
  }
  // Normalize weights into integers in [0, 2^16].
  double highest_weight = 0;
  double lowest_weight = 0;
  double weight_sum = 0;
  for (size_t i = 0; i < records_.size(); ++i) {
    if (i == 0 || weights[i] > highest_weight) {
      highest_weight = weights[i];
    }
    if (i == 0 || weights[i] < lowest_weight) {
      lowest_weight = weights[i];
    }
    weight_sum += weights[i];
  }
  FUZZTEST_VLOG(1) << "Recomputed weight with average: "
                   << weight_sum / records_.size()
                   << " highest: " << highest_weight
                   << " lowest: " << lowest_weight;
  FUZZTEST_CHECK(lowest_weight >= 0) << "Must not have negative corpus weight!";
  for (size_t i = 0; i < records_.size(); ++i) {
    // If all weights are zeros, fall back to prioritize recent corpus.
    const double normalized_weight = highest_weight > 0
                                         ? (weights[i] / highest_weight)
                                         : ((i + 1.0) / records_.size());
    weighted_distribution_.ChangeWeight(i, normalized_weight * (1 << 16));
  }
  weighted_distribution_.RecomputeInternalState();
}

size_t Corpus::Prune(const FeatureSet &fs,
                     const CoverageFrontier &coverage_frontier,
                     size_t max_corpus_size, Rng &rng) {
  // TODO(kcc): use coverage_frontier.
  FUZZTEST_CHECK(max_corpus_size);
  if (records_.size() < 2UL) return 0;

  size_t num_zero_weights = 0;
  for (size_t i = 0; i < records_.size(); ++i) {
    if (weighted_distribution_.weights()[i] == 0) {
      ++num_zero_weights;
    }
  }

  // Remove zero weights and the corresponding corpus record.
  // Also remove some random elements, if the corpus is still too big.
  // The corpus must not be empty, hence target_size is at least 1.
  // It should also be <= max_corpus_size.
  size_t target_size = std::min(
      max_corpus_size, std::max(1UL, records_.size() - num_zero_weights));
  auto subset_to_remove =
      weighted_distribution_.RemoveRandomWeightedSubset(target_size, rng);
  if (subset_to_remove.size() == records_.size()) {
    // This can happen only when all inputs have zero weights - keep random one.
    FUZZTEST_CHECK(num_zero_weights == records_.size());
    subset_to_remove.erase(
        subset_to_remove.begin() +
        absl::Uniform<size_t>(rng, 0, subset_to_remove.size()));
  }
  RemoveSubset(subset_to_remove, records_);

  weighted_distribution_.RecomputeInternalState();
  FUZZTEST_CHECK(!records_.empty());

  // Features may have shrunk from CountUnseenAndPruneFrequentFeatures.
  // Call shrink_to_fit for the features that survived the pruning.
  for (auto &record : records_) {
    record.features.shrink_to_fit();
  }

  num_pruned_ += subset_to_remove.size();
  return subset_to_remove.size();
}

void Corpus::Add(const ByteArray& data, const FeatureVec& fv,
                 const ExecutionMetadata& metadata,
                 const ExecutionResult::Stats& stats, const FeatureSet& fs,
                 const CoverageFrontier& coverage_frontier) {
  // TODO(kcc): use coverage_frontier.
  FUZZTEST_CHECK(!data.empty())
      << "Got request to add empty element to corpus: ignoring";
  FUZZTEST_CHECK_EQ(records_.size(), weighted_distribution_.size());
  records_.push_back({data, fv, metadata, stats});
  // Will be updated by `UpdateWeights`.
  weighted_distribution_.AddWeight(0);
}

const CorpusRecord& Corpus::WeightedRandom(absl::BitGenRef rng) const {
  return records_[weighted_distribution_.RandomIndex(rng)];
}

const CorpusRecord& Corpus::UniformRandom(absl::BitGenRef rng) const {
  return records_[absl::Uniform<size_t>(rng, 0, records_.size())];
}

void Corpus::DumpStatsToFile(const FeatureSet &fs, std::string_view filepath,
                             std::string_view description) {
  auto *file = ValueOrDie(RemoteFileOpen(filepath, "w"));
  FUZZTEST_CHECK(file != nullptr) << "Failed to open file: " << filepath;
  FUZZTEST_CHECK_OK(RemoteFileSetWriteBufferSize(file, 100UL * 1024 * 1024));
  static constexpr std::string_view kHeaderStub = R"(# $0
{
  "num_inputs": $1,
  "corpus_stats": [)";
  static constexpr std::string_view kRecordStub = R"($0
    {"size": $1, "frequencies": [$2]})";
  static constexpr std::string_view kFooter = R"(
  ]
}
)";
  const std::string header_str =
      absl::Substitute(kHeaderStub, description, records_.size());
  FUZZTEST_CHECK_OK(RemoteFileAppend(file, header_str));
  std::string before_record;
  for (const auto &record : records_) {
    std::vector<size_t> frequencies;
    frequencies.reserve(record.features.size());
    for (const auto feature : record.features) {
      frequencies.push_back(fs.Frequency(feature));
    }
    const std::string frequencies_str = absl::StrJoin(frequencies, ", ");
    const std::string record_str = absl::Substitute(
        kRecordStub, before_record, record.data.size(), frequencies_str);
    FUZZTEST_CHECK_OK(RemoteFileAppend(file, record_str));
    before_record = ",";
  }
  FUZZTEST_CHECK_OK(RemoteFileAppend(file, std::string{kFooter}));
  FUZZTEST_CHECK_OK(RemoteFileClose(file));
}

std::string Corpus::MemoryUsageString() const {
  size_t data_size = 0;
  size_t features_size = 0;
  for (const auto &record : records_) {
    data_size += record.data.capacity() * sizeof(record.data[0]);
    features_size += record.features.capacity() * sizeof(record.features[0]);
  }
  return absl::StrCat("d", data_size >> 20, "/f", features_size >> 20);
}

//------------------------------------------------------------------------------
//                          WeightedDistribution
//------------------------------------------------------------------------------

void WeightedDistribution::AddWeight(uint64_t weight) {
  FUZZTEST_CHECK_EQ(weights_.size(), cumulative_weights_.size());
  weights_.push_back(weight);
  if (cumulative_weights_.empty()) {
    cumulative_weights_.push_back(weight);
  } else {
    cumulative_weights_.push_back(cumulative_weights_.back() + weight);
  }
}

void WeightedDistribution::ChangeWeight(size_t idx, uint64_t new_weight) {
  FUZZTEST_CHECK_LT(idx, size());
  weights_[idx] = new_weight;
  cumulative_weights_valid_ = false;
}

__attribute__((noinline))  // to see it in profile.
void WeightedDistribution::RecomputeInternalState() {
  uint64_t partial_sum = 0;
  for (size_t i = 0, n = size(); i < n; i++) {
    partial_sum += weights_[i];
    cumulative_weights_[i] = partial_sum;
  }
  cumulative_weights_valid_ = true;
}

__attribute__((noinline))  // to see it in profile.
size_t WeightedDistribution::RandomIndex(absl::BitGenRef rng) const {
  FUZZTEST_CHECK(!weights_.empty());
  FUZZTEST_CHECK(cumulative_weights_valid_);
  const uint64_t sum_of_all_weights = cumulative_weights_.back();
  if (sum_of_all_weights == 0) {
    // Can't do much else here.
    return absl::Uniform<size_t>(rng, 0, size());
  }
  auto it =
      std::upper_bound(cumulative_weights_.begin(), cumulative_weights_.end(),
                       absl::Uniform<uint64_t>(rng, 0, sum_of_all_weights));
  FUZZTEST_CHECK(it != cumulative_weights_.end());
  const size_t index = it - cumulative_weights_.begin();
  FUZZTEST_CHECK(weights_[index] != 0);
  return index;
}

uint64_t WeightedDistribution::PopBack() {
  uint64_t result = weights_.back();
  weights_.pop_back();
  cumulative_weights_.pop_back();
  return result;
}

//------------------------------------------------------------------------------
//                            CoverageFrontier
//------------------------------------------------------------------------------

size_t CoverageFrontier::Compute(const Corpus &corpus) {
  return Compute(corpus.Records());
}

size_t CoverageFrontier::Compute(
    const std::vector<CorpusRecord> &corpus_records) {
  // Initialize the vectors.
  std::fill(frontier_.begin(), frontier_.end(), false);
  std::fill(frontier_weight_.begin(), frontier_weight_.end(), 0);

  // A vector of covered indices in pc_table. Needed for Coverage object.
  PCIndexVec covered_pcs;
  for (const auto &record : corpus_records) {
    for (auto feature : record.features) {
      if (!feature_domains::kPCs.Contains(feature)) continue;
      size_t idx = ConvertPCFeatureToPcIndex(feature);
      if (idx >= binary_info_.pc_table.size()) continue;
      covered_pcs.push_back(idx);
      frontier_[idx] = true;
    }
  }

  Coverage coverage(binary_info_.pc_table, covered_pcs);

  num_functions_in_frontier_ = 0;
  IteratePcTableFunctions(binary_info_.pc_table, [this, &coverage](size_t beg,
                                                                   size_t end) {
    auto frontier_begin = frontier_.begin() + beg;
    auto frontier_end = frontier_.begin() + end;
    size_t cov_size_in_this_func =
        std::count(frontier_begin, frontier_end, true);

    if (cov_size_in_this_func > 0 && cov_size_in_this_func < end - beg)
      ++num_functions_in_frontier_;

    // Reset the frontier_ entries.
    std::fill(frontier_begin, frontier_end, false);

    // Iterate over BBs in the function and check the coverage statue.
    for (size_t i = beg; i < end; ++i) {
      // If the current pc is not covered, it cannot be a frontier.
      if (!coverage.BlockIsCovered(i)) continue;

      auto pc = binary_info_.pc_table[i].pc;

      // Current pc is covered, look for a non-covered successor.
      for (auto successor : binary_info_.control_flow_graph.GetSuccessors(pc)) {
        // Successor pc may not be in PCTable because of pruning.
        if (!binary_info_.control_flow_graph.IsInPcTable(successor)) continue;

        auto successor_idx =
            binary_info_.control_flow_graph.GetPcIndex(successor);

        // This successor is covered, skip it.
        if (coverage.BlockIsCovered(successor_idx)) continue;

        // Now we have a frontier, compute the weight.
        frontier_[i] = true;

        // Calculate frontier weight.
        // Here we use reachability and coverage to identify all reachable and
        // non-covered BBs from successor, and then use all functions called
        // in those BBs.
        for (auto reachable_bb :
             binary_info_.control_flow_graph.LazyGetReachabilityForPc(
                 successor)) {
          if (!binary_info_.control_flow_graph.IsInPcTable(reachable_bb) ||
              coverage.BlockIsCovered(
                  binary_info_.control_flow_graph.GetPcIndex(reachable_bb))) {
            // This reachable BB is already either processed and added or
            // covered via a different path -- not interesting!
            continue;
          }
          frontier_weight_[i] += ComputeFrontierWeight(
              coverage, binary_info_.control_flow_graph,
              binary_info_.call_graph.GetBasicBlockCallees(reachable_bb));
        }
      }
    }
  });

  return num_functions_in_frontier_;
}

}  // namespace fuzztest::internal
