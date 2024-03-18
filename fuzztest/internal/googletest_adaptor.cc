
#include "./fuzztest/internal/googletest_adaptor.h"

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/internal/configuration.h"
#include "./fuzztest/internal/corpus_database.h"
#include "./fuzztest/internal/io.h"
#include "./fuzztest/internal/registry.h"
#include "./fuzztest/internal/runtime.h"

namespace fuzztest::internal {

namespace {
template <typename T>
void RegisterFuzzTestAsGTest(int* argc, char*** argv, FuzzTest& test,
                             const Configuration& configuration,
                             absl::string_view suffix = "") {
  auto fixture_factory = [argc, argv, &test,
                          configuration = configuration]() -> T* {
    return new ::fuzztest::internal::GTest_TestAdaptor(test, argc, argv,
                                                       configuration);
  };
  const std::string test_name_with_suffix =
      absl::StrCat(test.test_name(), suffix);
  ::testing::RegisterTest(
      test.suite_name().c_str(), test_name_with_suffix.c_str(), nullptr,
      nullptr, test.file().c_str(), test.line(), std::move(fixture_factory));
}

template <typename T>
void RegisterSeparateRegressionTestForEachCrashingInput(
    int* argc, char*** argv, FuzzTest& test,
    const Configuration& configuration) {
  CorpusDatabase corpus_database(configuration);
  for (const std::string& input :
       corpus_database.GetCrashingInputsIfAny(test.full_name())) {
    Configuration updated_configuration = configuration;
    updated_configuration.crashing_input_to_reproduce = input;
    const std::string suffix =
        absl::StrCat("/Regression/", std::string(Basename(input)));
    RegisterFuzzTestAsGTest<T>(argc, argv, test, updated_configuration, suffix);
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

}  // namespace fuzztest::internal
