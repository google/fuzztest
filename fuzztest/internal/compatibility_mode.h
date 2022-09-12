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

// Experimental compatibility mode with external fuzzing engines implementing
// the LLVMFuzzerRunDriver interface. See:
// https://llvm.org/docs/LibFuzzer.html#using-libfuzzer-as-a-library
//
// This is only for benchmarking purposes of evaluating fuzzing effectiveness.
//
// Do NOT use in production.
#ifndef FUZZTEST_FUZZTEST_INTERNAL_RUNTIME_COMPATIBILITY_H_
#define FUZZTEST_FUZZTEST_INTERNAL_RUNTIME_COMPATIBILITY_H_

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "absl/random/distributions.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/time/clock.h"
#include "./fuzztest/internal/fixture_driver.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/runtime.h"

namespace fuzztest::internal {

#ifndef FUZZTEST_COMPATIBILITY_MODE

template <typename RegBase, typename Fixture, typename TargetFunction>
class FuzzTestExternalEngineAdaptor<RegBase, Fixture, TargetFunction> {};

#else

// Callback functions for the custom fuzzing logic when using external fuzzing
// engine.
class ExternalEngineCallback {
 public:
  virtual ~ExternalEngineCallback() = default;
  virtual void RunOneInputData(std::string_view data) = 0;
  virtual std::string MutateData(std::string_view data, size_t max_size,
                                 unsigned int seed) = 0;
};

// Sets and gets the global instance of libFuzzer callback object.
void SetExternalEngineCallback(ExternalEngineCallback* callback);
ExternalEngineCallback* GetExternalEngineCallback();

// Library API exposed from LibFuzzer.
extern "C" int LLVMFuzzerRunDriver(int* argc, char*** argv,
                                   int (*user_callback)(const uint8_t* data,
                                                        size_t size));

template <typename RegBase, typename Fixture, typename BaseFixture,
          typename... Args>
class FuzzTestExternalEngineAdaptor<
    RegBase, Fixture, void (BaseFixture::*)(Args...),
    std::enable_if_t<std::is_base_of_v<BaseFixture, Fixture> > >
    : public FuzzTestFuzzer, public ExternalEngineCallback {
 public:
  using TargetFunction = void (BaseFixture::*)(Args...);

  FuzzTestExternalEngineAdaptor(
      const FuzzTest& test,
      std::unique_ptr<FixtureDriver<RegBase, Fixture, TargetFunction> >
          fixture_driver)
      : test_(test), fixture_driver_staging_(std::move(fixture_driver)) {}

  void RunInUnitTestMode() override {
    GetFuzzerImpl().RunInUnitTestMode();
  };

  int RunInFuzzingMode(int* argc, char*** argv) override {
    FUZZTEST_INTERNAL_CHECK(&LLVMFuzzerRunDriver,
                            "LibFuzzer Driver API not defined.");
    FUZZTEST_INTERNAL_CHECK(
        GetExternalEngineCallback() == nullptr,
        "External engine callback is already set while running a fuzz test.");
    SetExternalEngineCallback(this);
    run_mode = RunMode::kFuzz;
    auto& impl = GetFuzzerImpl();
    on_failure.Enable(&impl.stats_, [] { return absl::Now(); });

    FUZZTEST_INTERNAL_CHECK(impl.fixture_driver_ != nullptr,
                            "Invalid fixture driver!");
    impl.fixture_driver_->SetUpFuzzTest();

    static bool driver_started = false;
    FUZZTEST_INTERNAL_CHECK(!driver_started, "Driver started more than once!");
    driver_started = true;
    LLVMFuzzerRunDriver(
        argc, argv, [](const uint8_t* data, size_t size) -> int {
          GetExternalEngineCallback()->RunOneInputData(
              std::string_view(reinterpret_cast<const char*>(data), size));
          return 0;
        });

    // If we're here, we didn't exit from RunOneInputData(), and hence we didn't
    // tear down the fixture.
    FUZZTEST_INTERNAL_CHECK(impl.fixture_driver_ != nullptr,
                            "Invalid fixture driver!");
    impl.fixture_driver_->TearDownFuzzTest();

    return 0;
  }

  // External engine callbacks.

  void RunOneInputData(std::string_view data) override {
    auto& impl = GetFuzzerImpl();
    if (impl.ShouldStop()) {
      FUZZTEST_INTERNAL_CHECK(impl.fixture_driver_ != nullptr,
                              "Invalid fixture driver!");
      impl.fixture_driver_->TearDownFuzzTest();
      on_failure.PrintFinalStatsOnDefaultSink();
      // Use _Exit instead of exit so libFuzzer does not treat it as a crash.
      std::_Exit(0);
    }
    on_failure.SetCurrentTest(&impl.test_);
    if (auto input = impl.TryParse(data)) {
      impl.RunOneInput({*std::move(input)});
    }
  }

  std::string MutateData(std::string_view data, size_t max_size,
                         unsigned int seed) override {
    auto& impl = GetFuzzerImpl();
    typename FuzzerImpl::PRNG prng(seed);
    auto input = impl.TryParse(data);
    if (!input) input = impl.params_domain_.Init(prng);
    constexpr int kNumAttempts = 10;
    std::string result;
    for (int i = 0; i < kNumAttempts; ++i) {
      auto copy = *input;
      for (int mutations_at_once = absl::Poisson<int>(prng) + 1;
           mutations_at_once > 0; --mutations_at_once) {
        impl.params_domain_.Mutate(copy, prng,
                                   /*only_shrink=*/max_size < data.size());
      }
      result = impl.params_domain_.SerializeCorpus(copy).ToString();
      if (result.size() <= max_size) break;
    }
    return result;
  }

 private:
  using FuzzerImpl = FuzzTestFuzzerImpl<RegBase, Fixture, TargetFunction>;

  FuzzerImpl& GetFuzzerImpl() {
    // Postpone the creation to override libFuzzer signal setup.
    if (!fuzzer_impl_) {
      fuzzer_impl_ = std::make_unique<FuzzerImpl>(
          test_, std::move(fixture_driver_staging_));
      fixture_driver_staging_ = nullptr;
    }
    return *fuzzer_impl_;
  }

  const FuzzTest& test_;
  // Stores the fixture driver before the fuzzer gets instantiated. Once
  // `fuzzer_impl_` is no longer nullptr, `fixture_driver_staging_` becomes
  // nullptr.
  std::unique_ptr<FixtureDriver<RegBase, Fixture, TargetFunction> >
      fixture_driver_staging_;
  std::unique_ptr<FuzzerImpl> fuzzer_impl_;
};

#endif  // FUZZTEST_COMPATIBILITY_MODE

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_RUNTIME_COMPATIBILITY_H_
