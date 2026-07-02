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

#include <atomic>
#include <cstdlib>

#include "absl/time/clock.h"
#include "absl/time/time.h"

namespace fuzztest::internal {

bool StopCondition::EarlyStopRequested() const {
  return early_stop_.load(std::memory_order_acquire).is_requested;
}

void StopCondition::ClearEarlyStopRequest() {
  early_stop_.store({}, std::memory_order_release);
}

void StopCondition::SetStopTime(absl::Time stop_time) {
  stop_time_ = stop_time;
}

void StopCondition::RequestEarlyStop(int exit_code) {
  early_stop_.store({exit_code, true}, std::memory_order_release);
}

absl::Time StopCondition::GetStopTime() const { return stop_time_; }

bool StopCondition::ShouldStop() const {
  return EarlyStopRequested() || stop_time_ < absl::Now();
}

int StopCondition::ExitCode() const {
  return early_stop_.load(std::memory_order_acquire).exit_code;
}

}  // namespace fuzztest::internal
