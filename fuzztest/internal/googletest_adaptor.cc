#include "./fuzztest/internal/googletest_adaptor.h"

#include <optional>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/functional/function_ref.h"
#include "absl/strings/str_cat.h"
#include "./fuzztest/internal/registry.h"

namespace fuzztest::internal {

void RunExpectExit(absl::FunctionRef<void()> test) {
#if defined(__APPLE__) || defined(_MSC_VER)
  test();
#else
  EXPECT_EXIT(test(), ::testing::ExitedWithCode(0), "");
#endif
}

#define run
void RegisterFuzzTestsAsGoogleTests(
    int* argc, char*** argv, const std::vector<std::string>& crashing_inputs) {
  ::fuzztest::internal::ForEachTest([&](auto& test) {
    auto fixture_factory =
        [argc, argv, &test]() -> ::fuzztest::internal::GTest_TestAdaptor* {
      return new ::fuzztest::internal::GTest_TestAdaptor(test, argc, argv,
                                                         std::nullopt);
    };
    auto test_factory = [argc, argv, &test]() -> ::testing::Test* {
      return new ::fuzztest::internal::GTest_TestAdaptor(test, argc, argv,
                                                         std::nullopt);
    };
    if (test.uses_fixture()) {
      ::testing::RegisterTest(test.suite_name(), test.test_name(), nullptr,
                              nullptr, test.file(), test.line(),
                              std::move(fixture_factory));
    } else {
      ::testing::RegisterTest(test.suite_name(), test.test_name(), nullptr,
                              nullptr, test.file(), test.line(),
                              std::move(test_factory));
    }
  });

  ::testing::UnitTest::GetInstance()->listeners().Append(
      new ::fuzztest::internal::GTest_EventListener<
          ::testing::EmptyTestEventListener, ::testing::TestPartResult>());
}

}  // namespace fuzztest::internal
