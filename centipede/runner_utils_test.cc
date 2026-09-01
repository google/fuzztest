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

#include <string_view>

#include "gtest/gtest.h"

namespace fuzztest::internal {
namespace {

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

}  // namespace
}  // namespace fuzztest::internal
