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

#include <memory>
#include <type_traits>
#include <utility>

#include "absl/functional/function_ref.h"
#include "absl/strings/string_view.h"
#ifdef FUZZTEST_USE_CENTIPEDE
#include "./fuzztest/internal/centipede_adaptor.h"
#endif
#ifdef FUZZTEST_COMPATIBILITY_MODE
#include "./fuzztest/internal/compatibility_mode.h"
#endif
#include "./fuzztest/internal/fixture_driver.h"
#include "./fuzztest/internal/registration.h"
#include "./fuzztest/internal/runtime.h"

namespace fuzztest::internal {

void RegisterImpl(BasicTestInfo test_info, FuzzTestFuzzerFactory factory);

void ForEachTest(absl::FunctionRef<void(FuzzTest&)> func);

using SetUpTearDownTestSuiteFunction = void (*)();

void RegisterSetUpTearDownTestSuiteFunctions(
    absl::string_view suite_name,
    SetUpTearDownTestSuiteFunction set_up_test_suite,
    SetUpTearDownTestSuiteFunction tear_down_test_suite);

SetUpTearDownTestSuiteFunction GetSetUpTestSuite(absl::string_view suite_name);

SetUpTearDownTestSuiteFunction GetTearDownTestSuite(
    absl::string_view suite_name);

struct RegistrationToken {
  template <typename RegBase, typename Fixture, typename TargetFunction,
            typename SeedProvider>
  RegistrationToken& operator=(
      Registration<Fixture, TargetFunction, RegBase, SeedProvider>&& reg) {
    if constexpr (std::is_base_of_v<FixtureWithExplicitSetUp, Fixture>) {
      RegisterSetUpTearDownTestSuiteFunctions(reg.test_info_.suite_name,
                                              &Fixture::SetUpTestSuite,
                                              &Fixture::TearDownTestSuite);
    }
    BasicTestInfo test_info = reg.test_info_;
    RegisterImpl(std::move(test_info),
                 GetFuzzTestFuzzerFactory(std::move(reg)));
    return *this;
  }

  template <typename RegBase, typename Fixture, typename TargetFunction,
            typename SeedProvider>
  FuzzTestFuzzerFactory GetFuzzTestFuzzerFactory(
      Registration<Fixture, TargetFunction, RegBase, SeedProvider>&& reg) {
#if defined(FUZZTEST_COMPATIBILITY_MODE) && defined(FUZZTEST_USE_CENTIPEDE)
#error FuzzTest compatibility mode cannot work together with Centipede.
#endif
#if defined(FUZZTEST_COMPATIBILITY_MODE)
    using FuzzerImpl = FuzzTestExternalEngineAdaptor;
#elif defined(FUZZTEST_USE_CENTIPEDE)
    using FuzzerImpl = CentipedeFuzzerAdaptor;
#else
    using FuzzerImpl = FuzzTestFuzzerImpl;
#endif

    return [target_function = reg.target_function_, domain = reg.GetDomains(),
            seeds = reg.seeds(), seed_provider = reg.seed_provider()](
               const FuzzTest& test) -> std::unique_ptr<FuzzTestFuzzer> {
      return std::make_unique<FuzzerImpl>(
          test,
          std::make_unique<FixtureDriverImpl<decltype(domain), Fixture,
                                             TargetFunction, SeedProvider>>(
              target_function, domain, seeds, seed_provider));
    };
  }
};

// For those platforms we don't support yet.
struct RegisterStub {
  template <typename... T>
  RegisterStub WithDomains(T&&...) {
    return *this;
  }
};

#define INTERNAL_FUZZ_TEST(suite_name, func)                         \
  [[maybe_unused]] static ::fuzztest::internal::RegistrationToken    \
      fuzztest_reg_##suite_name##func =                              \
          ::fuzztest::internal::RegistrationToken{} =                \
              ::fuzztest::internal::Registration<                    \
                  ::fuzztest::internal::NoFixture, decltype(+func)>( \
                  {#suite_name, #func, __FILE__, __LINE__, false}, +func)

#define INTERNAL_FUZZ_TEST_F(suite_name, test_name, fixture, func)          \
  [[maybe_unused]] static ::fuzztest::internal::RegistrationToken           \
      fuzztest_reg_##suite_name##test_name =                                \
          ::fuzztest::internal::RegistrationToken{} =                       \
              ::fuzztest::internal::Registration<fixture,                   \
                                                 decltype(&fixture::func)>( \
                  {#suite_name, #test_name, __FILE__, __LINE__, true},      \
                  &fixture::func)

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_REGISTRY_H_
