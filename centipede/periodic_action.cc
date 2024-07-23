// Copyright 2024 The Centipede Authors.
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

#include "./centipede/periodic_action.h"

#include <utility>

#include "absl/functional/any_invocable.h"
#include "absl/log/check.h"
#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "absl/time/time.h"

namespace centipede {

PeriodicAction::PeriodicAction(  //
    absl::AnyInvocable<void()> action, Options options)
    : action_{std::move(action)},
      options_{std::move(options)},
      thread_{[this]() { RunLoop(); }} {
  // NOTE: Allow `options_.delay` to be `absl::InfiniteDuration()`: that's a
  // valid use case, where the run-loop actually starts looping only after a
  // first explicit nudge.
  CHECK_GT(options_.interval, absl::ZeroDuration());
}

PeriodicAction::~PeriodicAction() { Stop(); }

void PeriodicAction::Stop() {
  StopAsync();
  // The run-loop should exit the next time it checks `stop_`. Note that if
  // the loop is currently in the middle of an invocation of `action_`, it
  // will wait for the invocation to finish, so we might block here for an
  // `action_`-dependent amount of time.
  if (thread_.joinable()) {
    thread_.join();
  }
}

void PeriodicAction::StopAsync() {
  if (!stop_.HasBeenNotified()) {
    // Prime the run-loop to exit next time it re-checks `stop_`.
    stop_.Notify();
    // Nudge the run-loop out of the sleeping phase, if it's there: the loop
    // immediately goes to re-check `stop_` and exits.
    {
      absl::MutexLock lock{&nudge_mu_};
      nudge_ = true;
    }
  }
}

void PeriodicAction::Nudge() {
  absl::MutexLock lock{&nudge_mu_};
  nudge_ = true;
}

void PeriodicAction::RunLoop() {
  SleepUnlessWokenByNudge(options_.delay);
  while (!stop_.HasBeenNotified()) {
    action_();
    SleepUnlessWokenByNudge(options_.interval);
  }
}

void PeriodicAction::SleepUnlessWokenByNudge(absl::Duration duration) {
  if (nudge_mu_.WriterLockWhenWithTimeout(absl::Condition{&nudge_}, duration)) {
    // Got woken up by a nudge.
    nudge_mu_.AssertHeld();
    nudge_ = false;
  } else {
    // A nudge never came, slept well the entire time: nothing to do.
  }
  nudge_mu_.Unlock();
}

}  // namespace centipede
