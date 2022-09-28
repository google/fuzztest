// Copyright 2022 Google LLC
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

#include "./fuzztest/internal/runtime.h"

#include <memory>
#include <string>
#include <tuple>

#include "gtest/gtest.h"
#include "absl/time/time.h"
#include "./fuzztest/domain.h"
#include "./fuzztest/internal/domain.h"
#include "./fuzztest/internal/test_protobuf.pb.h"

namespace fuzztest::internal {
namespace {

TEST(OnFailureTest, Output) {
  const auto get_failure = [] {
    std::string s;
    on_failure.PrintReport(&s);
    return s;
  };
  // Disabled by default.
  EXPECT_EQ(get_failure(), "");

  FuzzTest test({"SUITE_NAME", "TEST_NAME", "FILE", 123}, nullptr);
  std::tuple args(17, std::string("ABC"));
  const RuntimeStats stats = {absl::FromUnixNanos(0), 1, 2, 3, 4};
  on_failure.Enable(&stats, [] { return absl::FromUnixNanos(1979); });
  run_mode = RunMode::kFuzz;
  auto domain = TupleOf(Arbitrary<int>(), Arbitrary<std::string>());
  OnFailure::Args<decltype(domain)> debug_args{args, domain};
  on_failure.SetCurrentTest(&test);
  on_failure.SetCurrentArgs(&debug_args);
  EXPECT_EQ(get_failure(), R"(
=================================================================
=== Fuzzing stats

Elapsed seconds (ns): 1979
Total runs: 1
Edges covered: 2
Total edges: 3
Corpus size: 4

=================================================================
=== BUG FOUND!

FILE:123: Counterexample found for SUITE_NAME.TEST_NAME.
The test fails with input:
argument 0: 17
argument 1: "ABC"

=================================================================
=== Reproducer test

TEST(SUITE_NAME, TEST_NAMERegression) {
  TEST_NAME(
    17,
    "ABC"
  );
}

=================================================================
)");

  on_failure.Disable();
  EXPECT_EQ(get_failure(), "");
}

}  // namespace
}  // namespace fuzztest::internal
