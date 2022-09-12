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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_REGISTRY_H_
#define FUZZTEST_FUZZTEST_INTERNAL_REGISTRY_H_

#include <functional>
#include <memory>
#include <string_view>
#include <type_traits>
#include <utility>

#include "./fuzztest/internal/compatibility_mode.h"
#include "./fuzztest/internal/fixture_driver.h"
#include "./fuzztest/internal/registration.h"
#include "./fuzztest/internal/runtime.h"

namespace fuzztest::internal {

void RegisterImpl(BasicTestInfo test_info, FuzzTestFuzzerFactory factory);

void ForEachTest(const std::function<void(const FuzzTest&)>&);

template <typename RegBase, typename Fixture, typename TargetFunction>
FuzzTestFuzzerFactory GetFuzzTestFuzzerFactory(
    Registration<Fixture, TargetFunction, RegBase>&& reg) {
#ifdef FUZZTEST_COMPATIBILITY_MODE
  using FuzzerImpl =
      FuzzTestExternalEngineAdaptor<RegBase, Fixture, TargetFunction>;
#else
  using FuzzerImpl = FuzzTestFuzzerImpl<RegBase, Fixture, TargetFunction>;
#endif  // FUZZTEST_COMPATIBILITY_MODE

  return [reg = std::move(reg)](const FuzzTest& test) {
    return std::make_unique<FuzzerImpl>(
        test,
        std::make_unique<FixtureDriverImpl<RegBase, Fixture, TargetFunction>>(
            reg));
  };
}

using SetUpTearDownTestSuiteFunction = void (*)();

void RegisterSetUpTearDownTestSuiteFunctions(
    std::string_view suite_name,
    SetUpTearDownTestSuiteFunction set_up_test_suite,
    SetUpTearDownTestSuiteFunction tear_down_test_suite);

SetUpTearDownTestSuiteFunction GetSetUpTestSuite(std::string_view suite_name);

SetUpTearDownTestSuiteFunction GetTearDownTestSuite(
    std::string_view suite_name);

struct RegistrationToken {
  template <typename RegBase, typename Fixture, typename TargetFunction>
  RegistrationToken& operator=(
      Registration<Fixture, TargetFunction, RegBase>&& reg) {
    const BasicTestInfo test_info = reg.test_info_;
    RegisterImpl(test_info, GetFuzzTestFuzzerFactory(std::move(reg)));
    if constexpr (std::is_base_of_v<FixtureWithExplicitSetUp, Fixture>) {
      RegisterSetUpTearDownTestSuiteFunctions(test_info.suite_name,
                                              &Fixture::SetUpTestSuite,
                                              &Fixture::TearDownTestSuite);
    }
    return *this;
  }
};

// For those platforms we don't support yet.
struct RegisterStub {
  template <typename... T>
  RegisterStub WithDomains(T&&...) {
    return *this;
  }
};

#define INTERNAL_FUZZ_TEST_F(suite_name, test_name, uses_fixture, fixture,     \
                             func)                                             \
  [[maybe_unused]] static ::fuzztest::internal::RegistrationToken              \
      fuzztest_reg_##suite_name##test_name =                                   \
          ::fuzztest::internal::RegistrationToken{} =                          \
              ::fuzztest::internal::Registration<fixture,                      \
                                                 decltype(&fixture::func)>(    \
                  {#suite_name, #test_name, __FILE__, __LINE__, uses_fixture}, \
                  &fixture::func)

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_REGISTRY_H_
