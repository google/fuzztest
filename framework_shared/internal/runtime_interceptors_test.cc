// Copyright 2026 Google LLC
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

#include <pthread.h>

#include <cstddef>

#include "gtest/gtest.h"
#include "./common/logging.h"
#include "./framework_shared/sancov_runtime.h"

namespace fuzztest::internal {
namespace {

void* IncrementArg(void* arg) {
  ++(*static_cast<int*>(arg));
  return arg;
}

TEST(RuntimeInterceptorsTest, PthreadCreateRunsStartRoutine) {
  // Reference sancov_runtime so the linker pulls in runtime_interceptors.cc.
  SanCovRuntimeClearCoverage(/*full_clear=*/false);

  int counter = 0;
  pthread_t thread;
  ASSERT_EQ(pthread_create(&thread, nullptr, IncrementArg, &counter), 0);
  void* retval = nullptr;
  FUZZTEST_CHECK_EQ(pthread_join(thread, &retval), 0);
  EXPECT_EQ(counter, 1);
  EXPECT_EQ(retval, &counter);
}

TEST(RuntimeInterceptorsTest, FailedPthreadCreateDoesNotRunStartRoutineOrLeak) {
  SanCovRuntimeClearCoverage(/*full_clear=*/false);

  pthread_attr_t attr;
  FUZZTEST_CHECK_EQ(pthread_attr_init(&attr), 0);
  // Request an unallocatable stack size so pthread_create deterministically
  // fails without spawning a thread (checked under LSan/ASan for leaks of
  // ThreadCreateArgs).
  constexpr size_t kUnallocatableStackSize = size_t{1}
                                             << (sizeof(size_t) >= 8 ? 60 : 31);
  FUZZTEST_CHECK_EQ(pthread_attr_setstacksize(&attr, kUnallocatableStackSize),
                    0);

  int counter = 0;
  pthread_t thread;
  EXPECT_NE(pthread_create(&thread, &attr, IncrementArg, &counter), 0);
  EXPECT_EQ(counter, 0);

  FUZZTEST_CHECK_EQ(pthread_attr_destroy(&attr), 0);
}

}  // namespace
}  // namespace fuzztest::internal
