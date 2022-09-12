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

#include "googletest/include/gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
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

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);

  absl::ParseCommandLine(argc, argv);

  if (absl::GetFlag(FLAGS_list_fuzz_tests)) {
    for (const auto& name : fuzztest::ListRegisteredTests()) {
      std::cout << name << '\n';
    }
    return 0;
  }

  auto fuzz = absl::GetFlag(FLAGS_fuzz);
  if (fuzz.empty()) {
    // Run all tests in the unit test mode.
    GOOGLEFUZZTEST_REGISTER_FOR_GOOGLETEST(fuzztest::RunMode::kUnitTest, &argc,
                                           &argv);
  } else {
    // Select a specific test to be run in the in fuzzing mode.
    const std::string matching_fuzz_test =
        fuzztest::GetMatchingFuzzTestOrExit(fuzz);
    GTEST_FLAG_SET(filter, matching_fuzz_test);
    GOOGLEFUZZTEST_REGISTER_FOR_GOOGLETEST(fuzztest::RunMode::kFuzz, &argc,
                                           &argv);
  }
  return RUN_ALL_TESTS();
}
