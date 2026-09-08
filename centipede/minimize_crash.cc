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

#include "./centipede/minimize_crash.h"

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <optional>
#include <string>
#include <string_view>
#include <system_error>  // NOLINT
#include <utility>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_set.h"
#include "absl/synchronization/mutex.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/environment.h"
#include "./centipede/mutation_data.h"
#include "./centipede/runner_result.h"
#include "./centipede/stop.h"
#include "./centipede/thread_pool.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"
#include "./common/defs.h"
#include "./common/hash.h"
#include "./common/logging.h"  // IWYU pragma: keep

namespace fuzztest::internal {

namespace {

// The minimizer state shared by all worker threads.
// Thread-safe.
class MinimizerState {
 public:
  MinimizerState(size_t capacity, ByteSpan initial_crasher)
      : capacity_(capacity),
        crashers_{{initial_crasher.begin(), initial_crasher.end()}} {}

  std::vector<ByteArray> GetCurrentCrashers() {
    absl::MutexLock lock(mutex_);
    return {crashers_.begin(), crashers_.end()};
  }

  void AddCrasher(ByteArray crasher, std::string description) {
    absl::MutexLock lock(mutex_);
    if (!minimize_result_.has_value() ||
        crasher.size() < minimize_result_->input.size()) {
      minimize_result_ = {crasher, std::move(description)};
    }
    crashers_.insert(std::move(crasher));
    while (crashers_.size() > capacity_) {
      crashers_.erase(std::max_element(
          crashers_.begin(), crashers_.end(),
          [](const auto& a, const auto& b) { return a.size() < b.size(); }));
    }
  }

  std::optional<MinimizeCrashResult> GetMinimizeResult() {
    absl::MutexLock lock(mutex_);
    return minimize_result_;
  }

 private:
  mutable absl::Mutex mutex_;
  size_t capacity_ ABSL_GUARDED_BY(mutex_);
  // Keep at most `capacity_` crashers to avoid being stuck in local minimum.
  absl::flat_hash_set<ByteArray> crashers_ ABSL_GUARDED_BY(mutex_);
  std::optional<MinimizeCrashResult> minimize_result_ ABSL_GUARDED_BY(mutex_);
};

void MinimizeCrashInOneThread(const Environment& env,
                              CentipedeCallbacksFactory& callbacks_factory,
                              std::string_view crash_signature,
                              MinimizerState& state,
                              StopCondition& stop_condition) {
  ScopedCentipedeCallbacks scoped_callback(callbacks_factory, env,
                                           stop_condition);
  auto callbacks = scoped_callback.callbacks();
  BatchResult batch_result;

  size_t num_batches = env.num_runs / env.batch_size;
  for (size_t i = 0; i < num_batches; ++i) {
    if (stop_condition.ShouldStop()) break;
    FUZZTEST_LOG_EVERY_POW_2(INFO)
        << "[" << i << "] Minimizing... Interrupt to stop";

    const auto crashers = state.GetCurrentCrashers();
    FUZZTEST_CHECK(!crashers.empty());
    // Compute the minimal known crasher size.
    size_t min_known_size = crashers.front().size();
    for (const auto& crasher : crashers) {
      min_known_size = std::min(min_known_size, crasher.size());
    }

    std::vector<ByteSpan> smaller_mutants;
    // Create several mutants that are smaller than the current smallest one.
    //
    // Currently, we do this by calling the vanilla mutator and
    // discarding all inputs that are too large.
    //
    // TODO(xinhaoyuan): modify the Mutate() interface such that size hint can
    // be passed.
    const std::vector<Mutant> mutants = callbacks->Mutate(
        GetMutationInputRefsFromDataInputs(crashers), env.batch_size);
    for (const auto& m : mutants) {
      if (m.data.size() < min_known_size) {
        smaller_mutants.push_back(m.data);
      }
    }

    if (smaller_mutants.empty()) {
      continue;
    }

    // Try smaller mutants first to minimize the size of the new crasher.
    std::sort(smaller_mutants.begin(), smaller_mutants.end(),
              [](const auto& a, const auto& b) { return a.size() < b.size(); });

    // Execute all mutants. If a new crasher is found, add it to `state`.
    if (callbacks->Execute(env.binary, smaller_mutants, batch_result)) {
      continue;
    }

    if (batch_result.failure_signature() != crash_signature) {
      continue;
    }

    size_t crash_inputs_idx = batch_result.num_outputs_read();
    FUZZTEST_CHECK_LT(crash_inputs_idx, smaller_mutants.size());
    const auto& new_crasher = smaller_mutants[crash_inputs_idx];
    FUZZTEST_LOG(INFO) << "Crasher: size: " << new_crasher.size() << ": "
                       << AsPrintableString(new_crasher, /*max_len=*/40);
    state.AddCrasher({new_crasher.begin(), new_crasher.end()},
                     std::move(batch_result.failure_description()));
  }
}

}  // namespace

std::optional<MinimizeCrashResult> MinimizeCrash(
    ByteSpan crashy_input, const Environment& env,
    CentipedeCallbacksFactory& callbacks_factory,
    std::string_view crash_signature, StopCondition& stop_condition) {
  FUZZTEST_LOG(INFO) << "Starting the crash minimization loop in "
                     << env.num_threads << " threads";

  // Minimize with 20 intermediate crashers empirically - may be adjusted later.
  MinimizerState state(/*capacity=*/20, crashy_input);

  {
    ThreadPool threads{static_cast<int>(env.num_threads)};
    for (size_t i = 0; i < env.num_threads; ++i) {
      threads.Schedule([&env, &callbacks_factory, &state, &stop_condition,
                        crash_signature]() {
        CreateLocalDirRemovedAtExit(TemporaryLocalDirPath());
        MinimizeCrashInOneThread(env, callbacks_factory, crash_signature, state,
                                 stop_condition);
      });
    }
  }  // The threads join here.

  return state.GetMinimizeResult();
}

}  // namespace fuzztest::internal
