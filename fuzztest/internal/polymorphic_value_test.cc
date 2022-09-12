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

#include "./fuzztest/internal/polymorphic_value.h"

#include <string>
#include <type_traits>
#include <utility>

#include "googletest/include/gtest/gtest.h"
#include "absl/strings/str_cat.h"

namespace fuzztest::internal {
namespace {

TEST(PolymorphicValue, BasicOperationsWork) {
  PolymorphicValue<> v(std::in_place, 0);
  EXPECT_TRUE(v.Has<int>());
  EXPECT_FALSE(v.Has<double>());

  auto copy = v;
  ASSERT_TRUE(copy.Has<int>());
  EXPECT_FALSE(copy.Has<double>());
  EXPECT_EQ(copy.GetAs<int>(), 0);
}

TEST(PolymorphicValue, NonTrivialTypesWorkCopyAndDestroyCorrectly) {
  std::string str = "A very long string that uses heap.";
  PolymorphicValue<> v(std::in_place, str);
  EXPECT_EQ(str, v.GetAs<std::string>());
  EXPECT_EQ(str, PolymorphicValue<>(v).GetAs<std::string>());
}

struct PrintVisitor {
  template <typename T>
  std::string operator()(const T& v) {
    return absl::StrCat(v);
  }
};

struct IncrementVisitor {
  template <typename T>
  void operator()(T& v, int d) {
    v += d;
  }
};

TEST(PolymorphicValue, VisitingValueWorks) {
  using P = PolymorphicValue<PrintVisitor, IncrementVisitor>;
  P an_int(std::in_place, 10);
  P a_double(std::in_place, 1.5);

  EXPECT_EQ("10", an_int.Visit(PrintVisitor{}));
  EXPECT_EQ("1.5", a_double.Visit(PrintVisitor{}));

  an_int.Visit(IncrementVisitor{}, 8);
  a_double.Visit(IncrementVisitor{}, 10);

  EXPECT_EQ("18", an_int.Visit(PrintVisitor{}));
  EXPECT_EQ("11.5", a_double.Visit(PrintVisitor{}));

  // Can also print a const value because PrintVisitor takes by const&.
  EXPECT_EQ("18", std::as_const(an_int).Visit(PrintVisitor{}));
  EXPECT_EQ("11.5", std::as_const(a_double).Visit(PrintVisitor{}));
}

}  // namespace
}  // namespace fuzztest::internal
