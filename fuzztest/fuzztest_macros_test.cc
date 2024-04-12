#include "./fuzztest/fuzztest_macros.h"

#include <optional>
#include <string>

#include "gtest/gtest.h"
#include "absl/status/status.h"

namespace fuzztest::internal {
namespace {

struct UnescapeDictionaryEntryParam {
  std::string input;
  // Expected output if the input is valid, nullopt otherwise.
  std::optional<std::string> expected_output;
};

class UnescapeDictionaryEntryTest
    : public ::testing::TestWithParam<UnescapeDictionaryEntryParam> {};

TEST_P(UnescapeDictionaryEntryTest, Success) {
  const ParamType& param = GetParam();
  absl::StatusOr<std::string> unescaped_entry =
      UnescapeDictionaryEntry(param.input);
  if (param.expected_output.has_value()) {
    EXPECT_TRUE(unescaped_entry.ok()) << unescaped_entry.status().message();
    EXPECT_EQ(*unescaped_entry, param.expected_output.value());
  } else {
    EXPECT_EQ(unescaped_entry.status().code(),
              absl::StatusCode::kInvalidArgument);
  }
}

INSTANTIATE_TEST_SUITE_P(
    UnescapeDictionaryEntryTests, UnescapeDictionaryEntryTest,
    testing::Values(
        // The first 4 examples are from
        // https://llvm.org/docs/LibFuzzer.html#dictionaries
        UnescapeDictionaryEntryParam{.input = R"(blah)",
                                     .expected_output = "blah"},
        UnescapeDictionaryEntryParam{.input = R"(\"ac\\dc\")",
                                     .expected_output = "\"ac\\dc\""},
        UnescapeDictionaryEntryParam{.input = R"(\xF7\xF8)",
                                     .expected_output = "\xF7\xF8"},
        UnescapeDictionaryEntryParam{.input = R"(foo\x0Abar)",
                                     .expected_output = "foo\nbar"},
        UnescapeDictionaryEntryParam{.input = R"(Abc\xg0hi)",
                                     .expected_output = std::nullopt},
        UnescapeDictionaryEntryParam{.input = R"(Def\x)",
                                     .expected_output = std::nullopt},
        UnescapeDictionaryEntryParam{.input = R"(\777)",
                                     .expected_output = std::nullopt},
        UnescapeDictionaryEntryParam{.input = R"(u\u1v)",
                                     .expected_output = std::nullopt},
        UnescapeDictionaryEntryParam{.input = R"(u\Uffffffv)",
                                     .expected_output = std::nullopt}));

}  // namespace
}  // namespace fuzztest::internal
