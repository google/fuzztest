// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstddef>

#include "gtest/gtest.h"
#include "./fuzztest/fuzztest.h"

namespace {

volatile int force_write = 0;

// This test fails in two ways:
// 1. It fails with an assertion failure, e.g., when `v == {2025}`.
// 2. It fails with a heap buffer overflow, e.g., when `v == {4050}`.
void FailsInTwoWays(const std::vector<int>& v) {
  if (v.size() % 7 != 1) return;
  ASSERT_NE(v[0], 2025);
  if (v[0] == 2 * 2025) force_write = v.data()[v.size()];
}
FUZZ_TEST(FuzzTest, FailsInTwoWays);

int ReachStackOverflow(int n) {
  // Use volatile to prevent the compiler from inlining the recursion.
  volatile auto f = ReachStackOverflow;
  return n > 0 ? 1 + f(n - 1) : 0;
}

// Stack frame consists of at least one word.
constexpr size_t kStackFrameSizeLowerBound = sizeof(void*);
// Default stack limit is 128 KiB.
constexpr int kDepthToReachStackOverflow =
    128 * 1024 / kStackFrameSizeLowerBound;

void FailsWithStackOverflow(int n) { ReachStackOverflow(n); }
FUZZ_TEST(FuzzTest, FailsWithStackOverflow)
    .WithDomains(fuzztest::Just(kDepthToReachStackOverflow));

}  // namespace
