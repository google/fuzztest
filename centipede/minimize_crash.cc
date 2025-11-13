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
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>  // NOLINT
#include <utility>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/crash_deduplication.h"
#include "./centipede/environment.h"
#include "./centipede/mutation_input.h"
#include "./centipede/runner_result.h"
#include "./centipede/stop.h"
#include "./centipede/thread_pool.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"
#include "./common/defs.h"
#include "./common/hash.h"
#include "./common/logging.h"  // IWYU pragma: keep
#include "./common/remote_file.h"

namespace fuzztest::internal {

// The minimizer state shared by all worker threads.
// Thread-safe.
struct MinimizerState {
 public:
  // Creates the queue.
  // `crasher` is the initial crashy input.
  MinimizerState(size_t capacity, ByteArray crasher)
      : capacity_(capacity), crashers_{std::move(crasher)} {}

  // Returns up to `max_num_crashers` most recently added crashers.
  std::vector<ByteArray> GetCurrentCrashers() {
    absl::MutexLock lock(&mutex_);
    return {crashers_.begin(), crashers_.end()};
  }

  void AddCrasher(ByteArray new_crasher, CrashDetails details) {
    absl::MutexLock lock(&mutex_);
    if (crashers_.contains(new_crasher)) {
      return;
    }
    if (min_crasher_.empty() || new_crasher.size() < min_crasher_.size()) {
      min_crasher_ = new_crasher;
      min_crasher_details_ = std::move(details);
    }
    crashers_.insert(std::move(new_crasher));
    while (crashers_.size() > capacity_) {
      crashers_.erase(std::max_element(
          crashers_.begin(), crashers_.end(),
          [](const auto& a, const auto& b) { return a.size() < b.size(); }));
    }
  }

  std::optional<std::pair<ByteArray, CrashDetails>> GetMinCrasherAndDetails() {
    absl::MutexLock lock(&mutex_);
    if (min_crasher_.empty()) return std::nullopt;
    return std::make_pair(min_crasher_, min_crasher_details_);
  }

 private:
  mutable absl::Mutex mutex_;
  size_t capacity_ ABSL_GUARDED_BY(mutex_);
  absl::flat_hash_set<ByteArray> crashers_ ABSL_GUARDED_BY(mutex_);
  ByteArray min_crasher_ ABSL_GUARDED_BY(mutex_);
  CrashDetails min_crasher_details_ ABSL_GUARDED_BY(mutex_);
};

// Performs a minimization loop in one thread.
static void MinimizeCrash(const Environment& env,
                          CentipedeCallbacksFactory& callbacks_factory,
                          const std::string* crash_signature,
                          MinimizerState& state) {
  ScopedCentipedeCallbacks scoped_callback(callbacks_factory, env);
  auto callbacks = scoped_callback.callbacks();
  BatchResult batch_result;

  size_t num_batches = env.num_runs / env.batch_size;
  for (size_t i = 0; i < num_batches; ++i) {
    FUZZTEST_LOG_EVERY_POW_2(INFO)
        << "[" << i << "] Minimizing... Interrupt to stop";
    if (ShouldStop()) break;

    // Get up to kMaxNumCrashersToGet most recent crashers. We don't want just
    // the most recent crasher to avoid being stuck in local minimum.
    const auto crashers = state.GetCurrentCrashers();
    FUZZTEST_CHECK(!crashers.empty());
    // Compute the minimal known crasher size.
    size_t min_known_size = crashers.front().size();
    for (const auto& crasher : crashers) {
      min_known_size = std::min(min_known_size, crasher.size());
    }

    std::vector<ByteArray> smaller_mutants;
    // Create several mutants that are smaller than the current smallest one.
    //
    // Currently, we do this by calling the vanilla mutator and
    // discarding all inputs that are too large.
    //
    // TODO(xinhaoyuan): modify the Mutate() interface such that size hint can
    // be passed.
    const std::vector<ByteArray> mutants = callbacks->Mutate(
        GetMutationInputRefsFromDataInputs(crashers), env.batch_size);
    for (const auto& m : mutants) {
      if (m.size() < min_known_size) smaller_mutants.push_back(m);
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

    if (crash_signature != nullptr &&
        batch_result.failure_signature() != *crash_signature) {
      continue;
    }

    size_t crash_inputs_idx = batch_result.num_outputs_read();
    FUZZTEST_CHECK_LT(crash_inputs_idx, smaller_mutants.size());
    const auto& new_crasher = smaller_mutants[crash_inputs_idx];
    FUZZTEST_LOG(INFO) << "Crasher: size: " << new_crasher.size() << ": "
                       << AsPrintableString(new_crasher, /*max_len=*/40);
    state.AddCrasher(new_crasher,
                     {/*input_signature=*/Hash(new_crasher),
                      batch_result.failure_description(), /*input_path=*/""});
  }
}

absl::StatusOr<CrashDetails> MinimizeCrash(
    ByteSpan crashy_input, const Environment& env,
    CentipedeCallbacksFactory& callbacks_factory,
    const std::string* crash_signature, std::string_view output_dir) {
  ScopedCentipedeCallbacks scoped_callback(callbacks_factory, env);
  auto callbacks = scoped_callback.callbacks();

  std::unique_ptr<std::string> owned_crash_signature;
  ByteArray original_crashy_input(crashy_input.begin(), crashy_input.end());
  if (crash_signature == nullptr) {
    BatchResult batch_result;
    if (callbacks->Execute(env.binary, {original_crashy_input}, batch_result)) {
      return absl::NotFoundError("The original crashy input did not crash");
    }
    if (env.minimize_crash_with_signature) {
      owned_crash_signature =
          std::make_unique<std::string>(batch_result.failure_signature());
      crash_signature = owned_crash_signature.get();
    }
  }

  FUZZTEST_LOG(INFO) << "Starting the crash minimization loop in "
                     << env.num_threads << " threads";

  // Minimize with 20 intermediate crashers empirically - may be adjusted later.
  MinimizerState state(/*capacity=*/20, original_crashy_input);

  {
    ThreadPool threads{static_cast<int>(env.num_threads)};
    for (size_t i = 0; i < env.num_threads; ++i) {
      threads.Schedule([&env, &callbacks_factory, crash_signature, &state]() {
        MinimizeCrash(env, callbacks_factory, crash_signature, state);
      });
    }
  }  // The threads join here.

  auto crasher_and_details = state.GetMinCrasherAndDetails();
  if (!crasher_and_details.has_value()) {
    return absl::NotFoundError("no minimized crash found");
  }

  auto [crasher, details] = *std::move(crasher_and_details);
  const auto output_dir_path = std::filesystem::path{output_dir};
  std::error_code ec;
  std::filesystem::create_directories(output_dir_path, ec);
  if (ec) {
    return absl::InternalError(absl::StrCat("failed to create directory path ",
                                            output_dir, ": ", ec.message()));
  }
  details.input_path = output_dir_path / details.input_signature;
  const auto status = RemoteFileSetContents(details.input_path, crasher);
  if (!status.ok()) {
    return status;
  }
  return details;
}

}  // namespace fuzztest::internal
