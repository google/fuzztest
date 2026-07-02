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

#include "./centipede/stop.h"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <string_view>
#include <thread>  // NOLINT: for std::this_thread

#include "absl/time/clock.h"
#include "absl/time/time.h"

namespace fuzztest::internal {

StopCondition::StopCondition() { reason_.reserve(64); }

void StopCondition::SetStopTime(absl::Time stop_time) {
  stop_time_ = stop_time;
}

void StopCondition::ClearEarlyStopRequest() {
  if (!stop_requested_.load(std::memory_order_acquire)) {
    return;
  }
  // Wait until the request is fully written.
  while (!stop_request_ready_.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }

  exit_code_ = EXIT_SUCCESS;
  reason_.clear();

  stop_request_ready_.store(false, std::memory_order_release);
  stop_requested_.store(false, std::memory_order_release);
}

bool StopCondition::EarlyStopRequested(EarlyStopRequest* request) const {
  if (!stop_requested_.load(std::memory_order_acquire)) {
    return false;
  }
  if (request == nullptr) {
    return true;
  }
  // Wait until the request is fully written.
  while (!stop_request_ready_.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }
  request->exit_code = exit_code_;
  request->reason = reason_;
  return true;
}

void StopCondition::RequestEarlyStop(int exit_code, std::string_view reason) {
  // Only write the reason if it hasn't been requested yet, to avoid races
  // overwriting it, although races are rare.
  if (stop_requested_.exchange(true)) return;
  exit_code_ = exit_code;
  // Full-copy - may allocate memory.
  reason_ = reason;
  stop_request_ready_.store(true, std::memory_order_release);
}

void StopCondition::RequestEarlyStopInSignal(int exit_code,
                                             std::string_view reason) {
  // Only write the reason if it hasn't been requested yet, to avoid races
  // overwriting it, although races are rare.
  if (stop_requested_.exchange(true)) return;
  exit_code_ = exit_code;
  // Copy up to the capacity - should not allocate memory.
  const auto copy_len = std::min(reason_.capacity(), reason.size());
  reason_ = reason.substr(0, copy_len);
  stop_request_ready_.store(true, std::memory_order_release);
}

absl::Time StopCondition::GetStopTime() const { return stop_time_; }

bool StopCondition::ShouldStop() const {
  return EarlyStopRequested() || stop_time_ < absl::Now();
}

}  // namespace fuzztest::internal
