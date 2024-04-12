#include "./fuzztest/fuzztest_macros.h"

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"

namespace fuzztest::internal {
namespace {

using ::testing::ElementsAre;

TEST(ParseDictionaryTest, Success) {
  // Derived from https://llvm.org/docs/LibFuzzer.html#dictionaries
  std::string dictionary_content =
      R"(# Lines starting with '#' and empty lines are ignored.

# Adds "blah" (w/o quotes) to the dictionary.
kw1="blah"
# Use \\ for backslash and \" for quotes.
kw2="\"ac\\dc\""
# Use \xAB for hex values
kw3="\xF7\xF8"
# the name of the keyword followed by '=' may be omitted:
"foo\x0Abar"

# Null character is unescaped as well
"foo\x00bar"
)";
  absl::StatusOr<std::vector<std::string>> dictionary_entries =
      ParseDictionary(dictionary_content);
  ASSERT_TRUE(dictionary_entries.ok());
  EXPECT_THAT(*dictionary_entries,
              ElementsAre("blah", "\"ac\\dc\"", "\xF7\xF8", "foo\nbar",
                          std::string("foo\0bar", 7)));
}
TEST(ParseDictionaryTest, FailsWithNoQuote) {
  std::string dictionary_content = R"(kw1=world)";
  absl::StatusOr<std::vector<std::string>> dictionary_entries =
      ParseDictionary(dictionary_content);
  EXPECT_EQ(dictionary_entries.status().code(),
            absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(dictionary_entries.status().message(),
              "Unparseable dictionary entry at line 1: missing quotes");
}

TEST(ParseDictionaryTest, FailsWithNoClosingQuote) {
  std::string dictionary_content = R"(kw1="world)";
  absl::StatusOr<std::vector<std::string>> dictionary_entries =
      ParseDictionary(dictionary_content);
  EXPECT_EQ(dictionary_entries.status().code(),
            absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(dictionary_entries.status().message(),
              "Unparseable dictionary entry at line 1: entry must be enclosed "
              "in quotes");
}

TEST(ParseDictionaryTest, FailsWithInvalidEscapeSequence) {
  std::string dictionary_content = R"(
# Valid
kw1="Hello"

# Invalid
kw2="world\!"
)";
  absl::StatusOr<std::vector<std::string>> dictionary_entries =
      ParseDictionary(dictionary_content);
  EXPECT_EQ(dictionary_entries.status().code(),
            absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(dictionary_entries.status().message(),
              "Unparseable dictionary entry at line 6: Invalid escape sequence "
              "in dictionary entry: \\!");
}

TEST(ParseDictionaryTest, FailsWithEmptyHexEscapeSequence) {
  std::string dictionary_content = R"(
# Valid
kw1="Hello"

# Invalid
kw2="world\x"
)";
  absl::StatusOr<std::vector<std::string>> dictionary_entries =
      ParseDictionary(dictionary_content);
  EXPECT_EQ(dictionary_entries.status().code(),
            absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(dictionary_entries.status().message(),
              "Unparseable dictionary entry at line 6: Invalid escape sequence "
              "in dictionary entry: \\x");
}

TEST(ParseDictionaryTest, FailsWithHexEscapeSequenceWithSingleDigit) {
  std::string dictionary_content = R"(
# Valid
kw1="Hello"

# Invalid
kw2="world\x2"
)";
  absl::StatusOr<std::vector<std::string>> dictionary_entries =
      ParseDictionary(dictionary_content);
  EXPECT_EQ(dictionary_entries.status().code(),
            absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(dictionary_entries.status().message(),
              "Unparseable dictionary entry at line 6: Invalid escape sequence "
              "in dictionary entry: \\x");
}

TEST(ParseDictionaryTest, FailsWithInvalidTwoDigitHexEscapeSequence) {
  std::string dictionary_content = R"(
# Valid
kw1="Hello"

# Invalid
kw2="world\x5g"
)";
  absl::StatusOr<std::vector<std::string>> dictionary_entries =
      ParseDictionary(dictionary_content);
  EXPECT_EQ(dictionary_entries.status().code(),
            absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(
      dictionary_entries.status().message(),
      "Unparseable dictionary entry at line 6: Could not unescape \\x5g");
}

}  // namespace
}  // namespace fuzztest::internal
