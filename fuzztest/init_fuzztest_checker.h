// Copyright 2022 Google LLC
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

#ifndef FUZZTEST_FUZZTEST_INIT_FUZZTEST_CHECKER_H_
#define FUZZTEST_FUZZTEST_INIT_FUZZTEST_CHECKER_H_

#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/internal/registry.h"
#include "./fuzztest/internal/runtime.h"

namespace fuzztest {
namespace internal {

inline constexpr absl::string_view kInitFuzzTestFailureMessage =
    "FuzzTest was not initialized! "
    "FUZZ_TEST was registered, but InitFuzzTest was never "
    "called in main(). "
    "If you are using a custom main(), please call "
    "fuzztest::InitFuzzTest(&argc, &argv)"
    " before RUN_ALL_TESTS().";

inline void CheckFuzzTestInitialization() {
  if (HasRegisteredFuzzTests() && !Runtime::instance().init_fuzztest_called()) {
    ADD_FAILURE() << kInitFuzzTestFailureMessage;
  }
}

class FuzzTestInitVerificationListener
    : public ::testing::EmptyTestEventListener {
 public:
  void OnTestIterationStart(const ::testing::UnitTest&, int) override {
    CheckFuzzTestInitialization();
  }
};

inline bool RegisterFuzzTestInitVerification() {
  static bool registered = [] {
    ::testing::UnitTest::GetInstance()->listeners().Append(
        new FuzzTestInitVerificationListener);
    return true;
  }();
  return registered;
}

[[maybe_unused]] inline const bool g_fuzztest_init_checker_registered =
    RegisterFuzzTestInitVerification();

}  // namespace internal
}  // namespace fuzztest

#endif  // FUZZTEST_FUZZTEST_INIT_FUZZTEST_CHECKER_H_
