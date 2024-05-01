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

// `PeriodicAction` runs a separate thread that invokes a user-provided callback
// at the specified interval. The user can request an out-of-schedule invocation
// of the callback by "nudging" the action object.
//
// Example:
//   MyStats stats = ...;
//   PeriodicAction stats_logger{
//       [&stats]() { LOG(INFO) << "Current stats are: " << stats; },
//       {.delay = absl::Minutes(5), .interval = absl::Minutes(1)}
//   };
//   while (true) {
//     Foo();
//     Bar();
//     if (HaveUpdate()) {
//       stats_logger.Nudge();
//     }
//   }

#ifndef FUZZTEST_CENTIPEDE_PERIODIC_ACTION_H_
#define FUZZTEST_CENTIPEDE_PERIODIC_ACTION_H_

#include <memory>
#include <thread>  // NOLINT

#include "absl/base/thread_annotations.h"
#include "absl/functional/any_invocable.h"
#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "absl/time/time.h"

namespace centipede {

class PeriodicAction {
 public:
  struct Options {
    // A delay before the first invocation of the callback. Allowed to be
    // `absl::IniniteDuration()`: in that case, the periodic invocations are
    // initiated only by a first explicit `Nudge()` call.
    absl::Duration delay = absl::ZeroDuration();
    // The interval between the end of one invocation of the callback and the
    // start of another. Note that a nudge triggers an out-of-schedule
    // invocation and resets the timer (see `Nudge()`).
    absl::Duration interval = absl::InfiniteDuration();
  };

  PeriodicAction(absl::AnyInvocable<void()> action, Options options);

  // Non-copyable and non-movable.
  PeriodicAction(const PeriodicAction&) = delete;
  PeriodicAction& operator=(const PeriodicAction&) = delete;
  PeriodicAction(PeriodicAction&&) = delete;
  PeriodicAction& operator=(PeriodicAction&&) = delete;

  // Stops the periodic action via RAII. May block: waits for any currently
  // active invocation of the action to finish first before returning.
  ~PeriodicAction();

  // Stops the periodic action explicitly. May block: waits for any currently
  // active invocation of the action to finish first before returning.
  void Stop();
  // The same as `Stop()`, but returns immediately without waiting for any
  // currently active invocation to finish.
  void StopAsync();

  // Triggers an out-of-schedule invocation of the action and resets the
  // timer. If a previously scheduled or nudged invocation of the action is
  // currently active, it will be allowed to finish before the nudged one
  // starts. However, the `Nudge()` call itself returns immediately without
  // waiting for either one to finish.
  void Nudge();

 private:
  // The actual run-loop. Runs on the `thread_` and invokes `action_`
  // periodically, as controlled by `options_`, `stop_` and `nudge_`.
  void RunLoop();

  // Sleeps for up to `duration` amount of time, unless a `nudge_` comes, in
  // which case wakes up and returns immediately.
  void SleepUnlessWokenByNudge(absl::Duration duration);

  absl::AnyInvocable<void()> action_;
  const Options options_;

  // WARNING!!! The order below is important.

  absl::Notification stop_;
  absl::Mutex nudge_mu_;
  bool nudge_ ABSL_GUARDED_BY(nudge_mu_) = false;
  std::thread thread_;
};

}  // namespace centipede

#endif  // FUZZTEST_CENTIPEDE_PERIODIC_ACTION_H_
