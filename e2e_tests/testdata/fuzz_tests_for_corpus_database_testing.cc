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

}  // namespace
