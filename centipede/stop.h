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

#ifndef THIRD_PARTY_CENTIPEDE_STOP_H_
#define THIRD_PARTY_CENTIPEDE_STOP_H_

#include <atomic>
#include <cstdlib>

#include "absl/time/time.h"

namespace fuzztest::internal {

// Encapsulates the stop condition state for Centipede.
class StopCondition {
 public:
  StopCondition() = default;

  StopCondition(const StopCondition&) = delete;
  StopCondition& operator=(const StopCondition&) = delete;
  StopCondition(StopCondition&&) = delete;
  StopCondition& operator=(StopCondition&&) = delete;

  // Clears the request to stop early.
  //
  // REQUIRES: Must be called before starting concurrent threads that may invoke
  // the other methods on this object instance. Specifically, calling this
  // function concurrently with `EarlyStopRequested()` is not thread-safe.
  void ClearEarlyStopRequest();

  // Returns whether `RequestEarlyStop()` was called or not since the most
  // recent call to `ClearEarlyStopRequest()` (if any).
  //
  // ENSURES: Thread-safe unless with `ClearEarlyStopRequest()`.
  bool EarlyStopRequested() const;

  // Requests that Centipede soon stops whatever it is doing (fuzzing,
  // minimizing reproducer, etc.), with `exit_code` indicating success (zero) or
  // failure (non-zero).
  //
  // ENSURES: Thread-safe and safe to call from signal handlers.
  void RequestEarlyStop(int exit_code);

  // Sets the stop time.
  //
  // REQUIRES: Must be called before starting concurrent threads that may invoke
  // the functions defined in this class. Specifically, calling this function
  // concurrently with `ShouldStop()` and `GetStopTime()` is not thread-safe.
  void SetStopTime(absl::Time stop_time);

  // Returns true iff it is time to stop, either because the stopping time has
  // been reached or `RequestEarlyStop()` was called since the most recent call
  // to `ClearEarlyStopRequestAndSetStopTime()` (if any).
  //
  // ENSURES: Thread-safe.
  bool ShouldStop() const;

  // Returns the stop time set from the recent
  // `ClearEarlyStopRequestAndSetStopTime()`, or `absl::InfiniteFuture()` if it
  // was not set.
  //
  // ENSURES: Thread-safe.
  absl::Time GetStopTime() const;

  // Returns the value most recently passed to `RequestEarlyStop()` or 0 if
  // `RequestEarlyStop()` was not called since the most recent call to
  // `ClearEarlyStopRequestAndSetStopTime()` (if any).
  //
  // ENSURES: Thread-safe.
  int ExitCode() const;

 private:
  struct EarlyStop {
    int exit_code = EXIT_SUCCESS;
    bool is_requested = false;
  };
  static_assert(std::atomic<EarlyStop>::is_always_lock_free);
  std::atomic<EarlyStop> early_stop_{EarlyStop{}};
  absl::Time stop_time_ = absl::InfiniteFuture();
};
}  // namespace fuzztest::internal

#endif  // THIRD_PARTY_CENTIPEDE_STOP_H_
