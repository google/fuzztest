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

#include "./fuzztest/internal/enum_reflection.h"

#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"

namespace fuzztest::internal::enum_reflection {
namespace {

using ::testing::UnorderedElementsAre;

TEST(IsValidEnumValue, WithValidSuffixes) {
  EXPECT_TRUE(IsValidEnumValueSuffix("... V = kGreen]", "]"));
  EXPECT_TRUE(IsValidEnumValueSuffix("... V = Green]", "]"));
  EXPECT_TRUE(IsValidEnumValueSuffix("... V = _Value_123]", "]"));
  EXPECT_TRUE(IsValidEnumValueSuffix("... V = fuzztest::Color::kGreen]", "]"));
}

TEST(IsValidEnumValue, WithInvalidSuffixes) {
  EXPECT_FALSE(IsValidEnumValueSuffix("... V = kGreen", "]"));  // Missing ]
  EXPECT_FALSE(IsValidEnumValueSuffix("", "]"));                // Empty
  EXPECT_FALSE(IsValidEnumValueSuffix("]", "]"));               // Only ]
  EXPECT_FALSE(IsValidEnumValueSuffix("... V = 42]", "]"));  // Ends with number
  EXPECT_FALSE(
      IsValidEnumValueSuffix("... V = (Color)2]", "]"));   // Ends with number
  EXPECT_FALSE(IsValidEnumValueSuffix("... V = ]", "]"));  // Empty suffix
}

enum class MyTestEnum { kVal0 = 0, kVal_1 = 2, ABC = 3 };

TEST(GetEnumValues, ReturnsValidValues) {
  std::vector<MyTestEnum> values = GetEnumValues<MyTestEnum>();
  EXPECT_THAT(values,
              UnorderedElementsAre(MyTestEnum::kVal0, MyTestEnum::kVal_1,
                                   MyTestEnum::ABC));
}

TEST(HasEnumValuesInRange, ReturnsTrueForValidEnum) {
  EXPECT_TRUE(HasEnumValuesInRange<MyTestEnum>());
}

TEST(HasEnumValuesInRange, ReturnsFalseForOutOfRangeEnum) {
  enum class OutOfRangeEnum { kVal = 128 };
  enum class NegOutOfRangeEnum { kVal = -129 };

  EXPECT_FALSE(HasEnumValuesInRange<OutOfRangeEnum>());
  EXPECT_FALSE(HasEnumValuesInRange<NegOutOfRangeEnum>());
}

}  // namespace
}  // namespace fuzztest::internal::enum_reflection
