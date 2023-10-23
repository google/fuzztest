#include "./fuzztest/internal/googletest_adaptor.h"

#include "gtest/gtest.h"
#include "./fuzztest/internal/registry.h"

namespace fuzztest::internal {

void RegisterFuzzTestsAsGoogleTests(int* argc, char*** argv) {
  ::fuzztest::internal::ForEachTest([&](auto& test) {
    auto fixture_factory =
        [argc, argv, &test]() -> ::fuzztest::internal::GTest_TestAdaptor* {
      return new ::fuzztest::internal::GTest_TestAdaptor(test, argc, argv);
    };
    auto test_factory = [argc, argv, &test]() -> ::testing::Test* {
      return new ::fuzztest::internal::GTest_TestAdaptor(test, argc, argv);
    };
    if (test.uses_fixture()) {
      ::testing::RegisterTest(
          test.suite_name().c_str(), test.test_name().c_str(), nullptr, nullptr,
          test.file().c_str(), test.line(), std::move(fixture_factory));
    } else {
      ::testing::RegisterTest(
          test.suite_name().c_str(), test.test_name().c_str(), nullptr, nullptr,
          test.file().c_str(), test.line(), std::move(test_factory));
    }
  });

  ::testing::UnitTest::GetInstance()->listeners().Append(
      new ::fuzztest::internal::GTest_EventListener<
          ::testing::EmptyTestEventListener, ::testing::TestPartResult>());
}

}  // namespace fuzztest::internal
