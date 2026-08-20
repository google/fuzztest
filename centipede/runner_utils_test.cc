// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./centipede/runner_utils.h"

#include <cstddef>
#include <string>
#include <string_view>

#include "gtest/gtest.h"

namespace fuzztest::internal {
namespace {

using std::string_view_literals::operator""sv;

TEST(RunnerUtilsTest, UnescapeEngineFlagsEmptyBuffer) {
  char buf[] = "";
  EXPECT_EQ(UnescapeEngineFlags(buf, 0), 0);
}

TEST(RunnerUtilsTest, UnescapeEngineFlagsNoColons) {
  std::string s = "no_colons_here";
  EXPECT_EQ(UnescapeEngineFlags(s.data(), s.size()), 0);
}

TEST(RunnerUtilsTest, UnescapeEngineFlagsSingleColon) {
  std::string s1 = ":";
  EXPECT_EQ(UnescapeEngineFlags(s1.data(), s1.size()), 0);

  std::string s2 = ":only_leading";
  EXPECT_EQ(UnescapeEngineFlags(s2.data(), s2.size()), 0);

  std::string s3 = "only_trailing:";
  EXPECT_EQ(UnescapeEngineFlags(s3.data(), s3.size()), 0);

  std::string s4 = "middle:only";
  EXPECT_EQ(UnescapeEngineFlags(s4.data(), s4.size()), 0);
}

TEST(RunnerUtilsTest, UnescapeEngineFlagsEmptyFlags) {
  {
    std::string s = "::";
    const size_t len = UnescapeEngineFlags(s.data(), s.size());
    EXPECT_EQ(std::string_view(s.data(), len), "\0\0"sv);
  }
  {
    std::string s = ":::";
    const size_t len = UnescapeEngineFlags(s.data(), s.size());
    EXPECT_EQ(std::string_view(s.data(), len), "\0\0\0"sv);
  }
}

TEST(RunnerUtilsTest, UnescapeEngineFlagsSingleFlag) {
  {
    std::string s = ":flag:";
    const size_t len = UnescapeEngineFlags(s.data(), s.size());
    EXPECT_EQ(std::string_view(s.data(), len), "\0flag\0"sv);
  }
  {
    std::string s = ":key=value:";
    const size_t len = UnescapeEngineFlags(s.data(), s.size());
    EXPECT_EQ(std::string_view(s.data(), len), "\0key=value\0"sv);
  }
}

TEST(RunnerUtilsTest, UnescapeEngineFlagsMultipleFlags) {
  std::string s = ":flag1:flag2=val2:flag3:";
  const size_t len = UnescapeEngineFlags(s.data(), s.size());
  EXPECT_EQ(std::string_view(s.data(), len), "\0flag1\0flag2=val2\0flag3\0"sv);
}

TEST(RunnerUtilsTest, UnescapeEngineFlagsEscapedColon) {
  std::string s = R"(:flag=foo\:bar:flag2:)";
  const size_t len = UnescapeEngineFlags(s.data(), s.size());
  EXPECT_EQ(std::string_view(s.data(), len), "\0flag=foo:bar\0flag2\0"sv);
}

TEST(RunnerUtilsTest, UnescapeEngineFlagsEscapedBackslash) {
  std::string s = R"(:path=C\:\\dir\\foo\\bar:flag2:)";
  const size_t len = UnescapeEngineFlags(s.data(), s.size());
  EXPECT_EQ(std::string_view(s.data(), len),
            "\0path=C:\\dir\\foo\\bar\0flag2\0"sv);
}

TEST(RunnerUtilsTest, UnescapeEngineFlagsEscapedOtherChars) {
  std::string s = R"(:flag\=name=val\=123:)";
  const size_t len = UnescapeEngineFlags(s.data(), s.size());
  EXPECT_EQ(std::string_view(s.data(), len), "\0flag=name=val=123\0"sv);
}

TEST(RunnerUtilsTest, UnescapeEngineFlagsDropsCharsBeforeFirstColon) {
  std::string s = "junk_before:flag1:flag2:";
  const size_t len = UnescapeEngineFlags(s.data(), s.size());
  EXPECT_EQ(std::string_view(s.data(), len), "\0flag1\0flag2\0"sv);
}

TEST(RunnerUtilsTest, UnescapeEngineFlagsDropsCharsAfterLastColon) {
  std::string s = ":flag1:flag2:junk_after";
  const size_t len = UnescapeEngineFlags(s.data(), s.size());
  EXPECT_EQ(std::string_view(s.data(), len), "\0flag1\0flag2\0"sv);
}

TEST(RunnerUtilsTest, UnescapeEngineFlagsDropsCharsBeforeAndAfter) {
  std::string s = "prefix:flag1=1:flag2=2:suffix";
  const size_t len = UnescapeEngineFlags(s.data(), s.size());
  EXPECT_EQ(std::string_view(s.data(), len), "\0flag1=1\0flag2=2\0"sv);
}

TEST(RunnerUtilsTest, UnescapeEngineFlagsTrailingBackslash) {
  // Trailing backslash after the last valid colon.
  {
    std::string s = ":flag:\\";
    const size_t len = UnescapeEngineFlags(s.data(), s.size());
    EXPECT_EQ(std::string_view(s.data(), len), "\0flag\0"sv);
  }

  // Trailing backslash before colon could close.
  {
    std::string s = ":flag\\";
    EXPECT_EQ(UnescapeEngineFlags(s.data(), s.size()), 0);
  }

  // Escaped colon at the end: ":flag\:" means the second colon is escaped,
  // so there is no terminating unescaped colon.
  {
    std::string s = R"(:flag\:)";
    EXPECT_EQ(UnescapeEngineFlags(s.data(), s.size()), 0);
  }
}

TEST(RunnerUtilsTest, UnescapeEngineFlagsComplex) {
  std::string s = R"(ignored:a=1\:2:b=\\c\\:d\=4:done:ignored_too)";
  const size_t len = UnescapeEngineFlags(s.data(), s.size());
  EXPECT_EQ(std::string_view(s.data(), len), "\0a=1:2\0b=\\c\\\0d=4\0done\0"sv);
}

TEST(RunnerUtilsTest, EngineFlagHelperWorksWithoutFlags) {
  EngineFlagHelper helper(nullptr);
  EXPECT_FALSE(helper.HasSwitchFlag("foo"));
  EXPECT_EQ(helper.GetIntFlag("bar=", 42), 42);
  EXPECT_EQ(helper.GetStringFlag("baz="), nullptr);
}

TEST(RunnerUtilsTest, EngineFlagHelperWorksWithFlags) {
  EngineFlagHelper helper(":flag1:flag2=123:str=hello:");
  EXPECT_TRUE(helper.HasSwitchFlag("flag1"));
  EXPECT_FALSE(helper.HasSwitchFlag("flag"));
  EXPECT_FALSE(helper.HasSwitchFlag("flag1_extra"));
  EXPECT_FALSE(helper.HasSwitchFlag("flag2"));
  EXPECT_FALSE(helper.HasSwitchFlag("missing"));

  EXPECT_EQ(helper.GetIntFlag("flag2=", 0), 123);
  EXPECT_EQ(helper.GetIntFlag("missing=", 999), 999);

  EXPECT_STREQ(helper.GetStringFlag("str="), "hello");
  EXPECT_EQ(helper.GetStringFlag("missing="), nullptr);
}

TEST(RunnerUtilsTest, EngineFlagHelperGetsUnescapedFlags) {
  EngineFlagHelper helper(R"(:path=C\:\\dir\\foo:flag\=name=val\=123:)");
  EXPECT_STREQ(helper.GetStringFlag("path="), "C:\\dir\\foo");
  EXPECT_STREQ(helper.GetStringFlag("flag=name="), "val=123");
}

}  // namespace
}  // namespace fuzztest::internal
