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

#include "./fuzztest/internal/compatibility_mode.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include "absl/strings/str_format.h"
#include "./fuzztest/internal/logging.h"

namespace fuzztest::internal {

#ifdef FUZZTEST_COMPATIBILITY_MODE

static ExternalEngineCallback* external_engine_callback = nullptr;

void SetExternalEngineCallback(ExternalEngineCallback* callback) {
  external_engine_callback = callback;
}

ExternalEngineCallback* GetExternalEngineCallback() {
  return external_engine_callback;
}

// libFuzzer-style custom mutator interface for external engine.
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
                                          size_t max_size, unsigned int seed);

size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size, size_t max_size,
                               unsigned int seed) {
  ExternalEngineCallback* callback = GetExternalEngineCallback();
  FUZZTEST_INTERNAL_CHECK(
      callback,
      "External engine callback is unset while running the FuzzTest mutator.");
  const std::string mutated_data = callback->MutateData(
      std::string_view(reinterpret_cast<const char*>(data), size), max_size,
      seed);
  if (mutated_data.size() > max_size) {
    absl::FPrintF(GetStderr(),
                  "Mutated data is larger than the limit. Returning the "
                  "original data.\n");
    return size;
  }
  memcpy(data, mutated_data.data(), mutated_data.size());
  return mutated_data.size();
}

FuzzTestExternalEngineAdaptor::FuzzTestExternalEngineAdaptor(
    const FuzzTest& test, std::unique_ptr<Driver> fixture_driver)
    : test_(test), fixture_driver_staging_(std::move(fixture_driver)) {}

void FuzzTestExternalEngineAdaptor::RunInUnitTestMode() {
  GetFuzzerImpl().RunInUnitTestMode();
}

int FuzzTestExternalEngineAdaptor::RunInFuzzingMode(int* argc, char*** argv) {
  FUZZTEST_INTERNAL_CHECK(&LLVMFuzzerRunDriver,
                          "LibFuzzer Driver API not defined.");
  FUZZTEST_INTERNAL_CHECK(
      GetExternalEngineCallback() == nullptr,
      "External engine callback is already set while running a fuzz test.");
  SetExternalEngineCallback(this);
  runtime_.SetRunMode(RunMode::kFuzz);
  auto& impl = GetFuzzerImpl();
  runtime_.EnableReporter(&impl.stats_, [] { return absl::Now(); });

  FUZZTEST_INTERNAL_CHECK(impl.fixture_driver_ != nullptr,
                          "Invalid fixture driver!");
  impl.fixture_driver_->SetUpFuzzTest();

  static bool driver_started = false;
  FUZZTEST_INTERNAL_CHECK(!driver_started, "Driver started more than once!");
  driver_started = true;
  LLVMFuzzerRunDriver(argc, argv, [](const uint8_t* data, size_t size) -> int {
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

void FuzzTestExternalEngineAdaptor::RunOneInputData(std::string_view data) {
  auto& impl = GetFuzzerImpl();
  if (impl.ShouldStop()) {
    FUZZTEST_INTERNAL_CHECK(impl.fixture_driver_ != nullptr,
                            "Invalid fixture driver!");
    impl.fixture_driver_->TearDownFuzzTest();
    runtime_.PrintFinalStatsOnDefaultSink();
    // Use _Exit instead of exit so libFuzzer does not treat it as a crash.
    std::_Exit(0);
  }
  runtime_.SetCurrentTest(&impl.test_);
  if (auto input = impl.TryParse(data)) {
    impl.RunOneInput({*std::move(input)});
  }
}

std::string FuzzTestExternalEngineAdaptor::MutateData(std::string_view data,
                                                      size_t max_size,
                                                      unsigned int seed) {
  auto& impl = GetFuzzerImpl();
  typename FuzzerImpl::PRNG prng(seed);
  auto input = impl.TryParse(data);
  if (!input) input = impl.params_domain_->UntypedInit(prng);
  constexpr int kNumAttempts = 10;
  std::string result;
  for (int i = 0; i < kNumAttempts; ++i) {
    auto copy = *input;
    for (int mutations_at_once = absl::Poisson<int>(prng) + 1;
         mutations_at_once > 0; --mutations_at_once) {
      impl.params_domain_->UntypedMutate(
          copy, prng,
          /*only_shrink=*/max_size < data.size());
    }
    result = impl.params_domain_->UntypedSerializeCorpus(copy).ToString();
    if (result.size() <= max_size) break;
  }
  return result;
}

FuzzTestExternalEngineAdaptor::FuzzerImpl&
FuzzTestExternalEngineAdaptor::GetFuzzerImpl() {
  // Postpone the creation to override libFuzzer signal setup.
  if (!fuzzer_impl_) {
    fuzzer_impl_ =
        std::make_unique<FuzzerImpl>(test_, std::move(fixture_driver_staging_));
    fixture_driver_staging_ = nullptr;
  }
  return *fuzzer_impl_;
}

#endif  // FUZZTEST_COMPATIBILITY_MODE

}  // namespace fuzztest::internal
