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

#include <cstdint>
#include <memory>
#include <thread>
#include <utility>

#include "absl/base/thread_annotations.h"
#include "absl/functional/any_invocable.h"
#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "absl/time/time.h"

namespace centipede {

class PeriodicAction::Impl {
 public:
  Impl(absl::AnyInvocable<void()> action, PeriodicAction::Options options)
      : action_{std::move(action)},
        options_{std::move(options)},
        thread_{[this]() { RunLoop(); }} {}

  void Stop() {
    StopAsync();
    // The run-loop should exit the next time it checks `stop_`. Note that if
    // the loop is currently in the middle of an invocation of `action_`, it
    // will wait for the invocation to finish, so we might block here for an
    // `action_`-dependent amount of time.
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  void StopAsync() {
    if (!stop_.HasBeenNotified()) {
      // Prime the run-loop to exit next time it re-checks `stop_`.
      stop_.Notify();
      // Nudge the run-loop out of the sleeping phase, if it's currently idling
      // there: the loop immediately goes to re-check `stop_` and exits.
      {
        absl::MutexLock lock{&nudge_mu_};
        nudge_ = true;
      }
    }
  }

  void Nudge() {
    absl::MutexLock lock{&nudge_mu_};
    nudge_ = true;
  }

 private:
  void RunLoop() {
    uint64_t iteration = 0;
    while (!stop_.HasBeenNotified()) {
      SleepUnlessWokenByNudge(options_.sleep_before_each(iteration));
      if (!stop_.HasBeenNotified()) {
        action_();
      }
      ++iteration;
    }
  }

  void SleepUnlessWokenByNudge(absl::Duration duration) {
    if (nudge_mu_.WriterLockWhenWithTimeout(  //
            absl::Condition{&nudge_}, duration)) {
      // Got woken up by a nudge.
      nudge_mu_.AssertHeld();
      nudge_ = false;
    } else {
      // A nudge never came, slept well the entire time: nothing to do.
    }
    nudge_mu_.Unlock();
  }

  absl::AnyInvocable<void()> action_;
  PeriodicAction::Options options_;

  // WARNING!!! The order below is important.
  absl::Notification stop_;
  absl::Mutex nudge_mu_;
  bool nudge_ ABSL_GUARDED_BY(nudge_mu_) = false;
  std::thread thread_;
};

PeriodicAction::PeriodicAction(  //
    absl::AnyInvocable<void()> action, Options options)
    : pimpl_{std::make_unique<Impl>(std::move(action), std::move(options))} {}

PeriodicAction::~PeriodicAction() {
  // NOTE: `pimpl_` will be null if this object has been moved to another one.
  if (pimpl_ != nullptr) pimpl_->Stop();
}

void PeriodicAction::Stop() { pimpl_->Stop(); }

void PeriodicAction::StopAsync() { pimpl_->StopAsync(); }

void PeriodicAction::Nudge() { pimpl_->Nudge(); }

// NOTE: Even though these are defaulted, they still must be defined here in the
// .cc, because `Impl` is an incomplete type in the .h.
PeriodicAction::PeriodicAction(PeriodicAction&&) = default;
PeriodicAction& PeriodicAction::operator=(PeriodicAction&&) = default;

}  // namespace centipede
