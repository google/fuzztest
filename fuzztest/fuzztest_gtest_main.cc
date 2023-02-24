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

#include <iostream>
#include <string>
#include <string_view>

#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/time/time.h"
#include "./fuzztest/fuzztest.h"
#include "./fuzztest/googletest_adaptor.h"
#include "./fuzztest/internal/runtime.h"

ABSL_FLAG(bool, list_fuzz_tests, false,
          "Prints (to stdout) the list of fuzz test names that can be run with "
          "`--fuzz=<name>`");

ABSL_FLAG(std::string, fuzz, "",
          "If set to a test name, the given test is run in continuous fuzzing "
          "mode until it is stopped. E.g., `--fuzz=MySuite.MyPropTest`. It is "
          "also possible to provide part of the name, e.g., `--fuzz=MyProp`, "
          "if it matches a single fuzz test.");

ABSL_FLAG(absl::Duration, fuzz_for, absl::InfiniteDuration(),
          "Runs all fuzz tests in fuzzing mode for the specified duration. Can "
          "be combined with --fuzz to select a single fuzz tests, or "
          "with --gtest_filter to select a subset of fuzz tests.");

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);

  absl::ParseCommandLine(argc, argv);

  if (absl::GetFlag(FLAGS_list_fuzz_tests)) {
    for (const auto& name : fuzztest::ListRegisteredTests()) {
      std::cout << "[*] Fuzz test: " << name << '\n';
    }
    return 0;
  }

  const auto fuzz = absl::GetFlag(FLAGS_fuzz);
  const bool is_fuzz_specified = !fuzz.empty();

  if (is_fuzz_specified) {
    // Select a specific test to be run in the in fuzzing mode.
    const auto matching_fuzz_test = fuzztest::GetMatchingFuzzTestOrExit(fuzz);
    GTEST_FLAG_SET(filter, matching_fuzz_test);
  }

  const auto duration = absl::GetFlag(FLAGS_fuzz_for);
  const bool is_duration_specified =
      absl::ZeroDuration() < duration && duration < absl::InfiniteDuration();
  if (is_duration_specified) {
    fuzztest::internal::Runtime::instance().SetFuzzTimeLimit(duration);
  }
  if (is_fuzz_specified || is_duration_specified) {
    GOOGLEFUZZTEST_REGISTER_FOR_GOOGLETEST(fuzztest::RunMode::kFuzz, &argc,
                                           &argv);
  } else {
    GOOGLEFUZZTEST_REGISTER_FOR_GOOGLETEST(fuzztest::RunMode::kUnitTest, &argc,
                                           &argv);
  }
  return RUN_ALL_TESTS();
}
