
#include "./fuzztest/internal/googletest_adaptor.h"

#include <cstdlib>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "./common/logging.h"
#include "./fuzztest/internal/configuration.h"
#include "./fuzztest/internal/corpus_database.h"
#include "./fuzztest/internal/flag_name.h"
#include "./fuzztest/internal/registry.h"
#include "./fuzztest/internal/runtime.h"

#ifdef FUZZTEST_USE_CENTIPEDE
#include "./fuzztest/internal/centipede_adaptor.h"
#endif

namespace fuzztest::internal {

std::vector<std::string> GTest_TestAdaptor::GetFuzzTestsInCurrentShard() const {
  std::vector<std::string> result;
  for (const auto* test : GetRegisteredTests()) {
    if (!test->should_run()) continue;
    if (test->is_in_another_shard()) continue;
    for (const auto& fuzztest : configuration_.fuzz_tests) {
      if (fuzztest ==
          absl::StrCat(test->test_suite_name(), ".", test->name())) {
        result.push_back(fuzztest);
        break;
      }
    }
  }
  return result;
}

namespace {
template <typename T>
void RegisterFuzzTestAsGTest(int* argc, char*** argv, FuzzTest& test,
                             const Configuration& configuration,
                             absl::string_view crashing_input_path = "") {
  auto fixture_factory = [argc, argv, &test,
                          configuration = configuration]() mutable -> T* {
    return new ::fuzztest::internal::GTest_TestAdaptor(
        test, argc, argv, std::move(configuration));
  };
  if (crashing_input_path.empty()) {
    ::testing::RegisterTest(test.suite_name().c_str(), test.test_name().c_str(),
                            nullptr, nullptr, test.file().c_str(), test.line(),
                            std::move(fixture_factory));
    return;
  }
  const absl::StatusOr<std::string> regression_test_name =
      RegressionTestNameForCrashingInput(test.test_name(), crashing_input_path);
  if (!regression_test_name.ok()) {
    FUZZTEST_LOG(WARNING)
        << "Failed to get regression test name for crashing input "
        << crashing_input_path << ". Not registering a regression test for it. "
        << "Status: " << regression_test_name.status();
    return;
  }
  ::testing::RegisterTest(
      test.suite_name().c_str(), regression_test_name->c_str(), nullptr,
      nullptr, test.file().c_str(), test.line(), std::move(fixture_factory));
}

template <typename T>
void RegisterSeparateRegressionTestForEachCrashingInput(
    int* argc, char*** argv, FuzzTest& test,
    const Configuration& configuration) {
  if (!configuration.reproduce_findings_as_separate_tests) return;
#ifdef FUZZTEST_USE_CENTIPEDE
  const std::vector<std::string> crash_inputs =
      ListCrashIdsUsingCentipede(configuration, test.full_name());
#else
  CorpusDatabase corpus_database(configuration);
  const std::vector<std::string> crash_inputs =
      corpus_database.GetCrashingInputsIfAny(test.full_name());
#endif
  for (const std::string& input : crash_inputs) {
    Configuration updated_configuration = configuration;
    updated_configuration.crashing_input_to_reproduce = input;
    RegisterFuzzTestAsGTest<T>(argc, argv, test, updated_configuration, input);
  }
}

template <typename T>
void RegisterTests(int* argc, char*** argv, FuzzTest& test,
                   const Configuration& configuration) {
  RegisterFuzzTestAsGTest<T>(argc, argv, test, configuration);
  RegisterSeparateRegressionTestForEachCrashingInput<T>(argc, argv, test,
                                                        configuration);
}

}  // namespace

void RegisterFuzzTestsAsGoogleTests(int* argc, char*** argv,
                                    const Configuration& configuration) {
  ::fuzztest::internal::ForEachTest([&](auto& test) {
    if (test.uses_fixture()) {
      RegisterTests<::fuzztest::internal::GTest_TestAdaptor>(argc, argv, test,
                                                             configuration);
    } else {
      RegisterTests<::testing::Test>(argc, argv, test, configuration);
    }
  });

  ::testing::UnitTest::GetInstance()->listeners().Append(
      new ::fuzztest::internal::GTest_EventListener<
          ::testing::EmptyTestEventListener, ::testing::TestPartResult>());
}

// A singleton validator class with Run() called when GoogleTest begins to run
// the tests.
class FuzzTestListingModeValidator {
 public:
  void Run() {
    if (listing_mode_) {
      // Since InitFuzzTest calls std::exit after listing the fuzz tests, we
      // would not reach here if InitFuzzTest is called before.
      absl::FPrintF(stderr,
                    "[!] --" FUZZTEST_FLAG_PREFIX
                    "list_fuzz_tests not handled by InitFuzzTest - fuzz tests "
                    "would not be listed even if defined.\n");
      std::exit(0);
    }
  }

  void set_listing_mode(bool listing_mode) { listing_mode_ = listing_mode; }

  static FuzzTestListingModeValidator& GetInstance() {
    static auto* instance = [] {
      static_assert(
          std::is_trivially_destructible_v<FuzzTestListingModeValidator>);
      static FuzzTestListingModeValidator instance;
      instance.RegisterGoogleTestListener();
      return &instance;
    }();
    return *instance;
  }

 private:
  // Only constructible/callable from GetInstance() for the singleton.
  FuzzTestListingModeValidator() = default;
  void RegisterGoogleTestListener();

  bool listing_mode_ = false;
};

// The proxy GoogleTest listener that calls the validator, needed as a separate
// class since GoogleTest takes the life-time of the listener.
class ValidatorProxyListener : public testing::EmptyTestEventListener {
 public:
  void OnTestProgramStart(const testing::UnitTest& unit_test) override {
    validator_->Run();
  }

 private:
  friend class FuzzTestListingModeValidator;

  ValidatorProxyListener(FuzzTestListingModeValidator* validator)
      : validator_(validator) {}

  FuzzTestListingModeValidator* validator_;
};

void FuzzTestListingModeValidator::RegisterGoogleTestListener() {
  testing::UnitTest::GetInstance()->listeners().Append(
      new ValidatorProxyListener(this));
}

void SetFuzzTestListingModeValidatorForGoogleTest(bool listing_mode) {
  FuzzTestListingModeValidator::GetInstance().set_listing_mode(listing_mode);
}

std::vector<const testing::TestInfo*> GetRegisteredTests() {
  std::vector<const testing::TestInfo*> result;
  auto& unit_test = *testing::UnitTest::GetInstance();
  // TODO(b/416466508): Remove this call once the bug is fixed. This function is
  // internal to GoogleTest.
  unit_test.parameterized_test_registry().RegisterTests();
  for (int i = 0; i < unit_test.total_test_suite_count(); ++i) {
    for (int j = 0; j < unit_test.GetTestSuite(i)->total_test_count(); ++j) {
      result.push_back(unit_test.GetTestSuite(i)->GetTestInfo(j));
    }
  }
  return result;
}

}  // namespace fuzztest::internal
