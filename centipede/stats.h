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

#ifndef THIRD_PARTY_CENTIPEDE_STATS_H_
#define THIRD_PARTY_CENTIPEDE_STATS_H_

#include <atomic>
#include <cstddef>
#include <ostream>

#include "absl/types/span.h"
#include "./centipede/environment.h"

namespace centipede {

// A set of statistics about the fuzzing progress.
// Each worker thread has its own Stats object and updates it periodically.
// The updates must not be frequent for performance reasons.
// All such objects may be read synchronously by another thread,
// hence the use of atomics.
// These objects may also be accessed after all worker threads have joined.
struct Stats {
  std::atomic<uint64_t> num_covered_pcs;
  std::atomic<uint64_t> corpus_size;
  std::atomic<uint64_t> max_corpus_element_size;
  std::atomic<uint64_t> avg_corpus_element_size;
  std::atomic<uint64_t> num_executions;
};

// Takes a span of Stats objects `stats_vec` and the corresponding span of
// Environment objects `env_vec`. If the environments indicate the use of
// --experiment flag, prints the experiment summary to `os`. Otherwise, a no-op.
void PrintExperimentStats(absl::Span<const Stats> stats_vec,
                          absl::Span<const Environment> env_vec,
                          std::ostream& os);

// Takes a span of Stats objects `stats_vec` and prints a summary of the results
// to `os`, such that it can be ingested as a reward function by an ML system.
// To be used with knobs.
void PrintRewardValues(absl::Span<const Stats> stats_vec, std::ostream& os);

}  // namespace centipede
#endif  // THIRD_PARTY_CENTIPEDE_STATS_H_
