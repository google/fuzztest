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

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>

#include "absl/time/time.h"

namespace fuzztest::internal {

// Encapsulates the stop condition state for Centipede.
class StopCondition {
 public:
  StopCondition();

  StopCondition(const StopCondition&) = delete;
  StopCondition& operator=(const StopCondition&) = delete;
  StopCondition(StopCondition&&) = delete;
  StopCondition& operator=(StopCondition&&) = delete;

  // Clears the request to stop.
  //
  // REQUIRES: Must be called before starting concurrent threads that may invoke
  // the other methods on this object instance. Specifically, calling this
  // function concurrently with `StopRequested()` is not thread-safe.
  void ClearStopRequest();

  struct StopRequest {
    int exit_code = EXIT_SUCCESS;
    std::string reason;
  };

  // Returns whether `RequestStop()` was called or not since the most
  // recent call to `ClearStopRequest()` (if any). If `request` is not
  // null, copy the stop request to the referred instance when stop is
  // requested.
  //
  // ENSURES: Thread-safe unless with `ClearStopRequest()`.
  bool StopRequested(StopRequest* request = nullptr) const;

  // Requests that Centipede soon stops whatever it is doing (fuzzing,
  // minimizing reproducer, etc.), with `exit_code` indicating success (zero) or
  // failure (non-zero). The `reason` will be capped to the internal buffer
  // size.
  //
  // ENSURES: Thread-safe and safe to call in signal handlers.
  void RequestStop(int exit_code, std::string_view reason);

  // Sets the stop time.
  //
  // REQUIRES: Must be called before starting concurrent threads that may invoke
  // the functions defined in this class. Specifically, calling this function
  // concurrently with `ShouldStop()` and `GetStopTime()` is not thread-safe.
  void SetStopTime(absl::Time stop_time);

  // Returns true iff it is time to stop, either because the stopping time has
  // been reached or `RequestStop()` was called since the most recent call
  // to `ClearStopRequest()` (if any).
  //
  // ENSURES: Thread-safe.
  bool ShouldStop() const;

  // Returns the stop time set from the recent
  // `SetStopTime()`, or `absl::InfiniteFuture()` if it
  // was not set.
  //
  // ENSURES: Thread-safe.
  absl::Time GetStopTime() const;

 private:
  static constexpr size_t kReasonBufferSize = 500;

  absl::Time stop_time_ = absl::InfiniteFuture();
  // Set to true when `RequestStop` is requested.
  std::atomic<bool> stop_requested_ = false;
  int exit_code_ = EXIT_SUCCESS;
  std::unique_ptr<std::array<char, kReasonBufferSize>> reason_;
  size_t reason_len_ = 0;
  // Set to true when the fields between `stop_requested_` and
  // `stop_request_ready_` are fully set.
  std::atomic<bool> stop_request_ready_ = false;
};
}  // namespace fuzztest::internal

#endif  // THIRD_PARTY_CENTIPEDE_STOP_H_
