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

// Tests of domains whose values are pointers, such as UniquePtrOf, SharedPtrOf
// and SmartPointerOf.

#include <optional>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/random/random.h"
#include "./fuzztest/domain_core.h"
#include "./domain_tests/domain_testing.h"

namespace fuzztest {
namespace {

using ::testing::IsNull;
using ::testing::Optional;
using ::testing::UnorderedElementsAre;

template <typename Domain>
void TestSmartPointer(Domain domain) {
  absl::BitGen bitgen;
  // Smart pointers always make null values during Init.
  for (int i = 0; i < 10; ++i) {
    Value value(domain, bitgen);
    EXPECT_THAT(value.user_value, IsNull());

    Set<std::optional<int>> mutations;
    while (mutations.size() < 4) {
      value.Mutate(domain, bitgen, {}, false);
      mutations.insert(value.user_value ? std::optional(*value.user_value)
                                        : std::nullopt);
    }
    EXPECT_THAT(mutations, UnorderedElementsAre(std::nullopt, Optional(1),
                                                Optional(2), Optional(3)));
  }
}

struct MyCustomSmartPointer {
  using element_type = int;
  MyCustomSmartPointer() {}
  explicit MyCustomSmartPointer(int* x) : i(x) {}

  friend bool operator==(const MyCustomSmartPointer& p, std::nullptr_t) {
    return p.i == nullptr;
  }

  int operator*() const { return *i; }
  explicit operator bool() const { return static_cast<bool>(i); }
  const int* get() const { return i.get(); }
  int* get() { return i.get(); }

  std::unique_ptr<int> i;
};

TEST(SmartPointerOf, CanMakeValuesOrNull) {
  TestSmartPointer(SmartPointerOf<std::unique_ptr<int>>(InRange(1, 3)));
  TestSmartPointer(SmartPointerOf<std::shared_ptr<int>>(InRange(1, 3)));
  TestSmartPointer(UniquePtrOf(InRange(1, 3)));
  TestSmartPointer(SharedPtrOf(InRange(1, 3)));
  TestSmartPointer(SmartPointerOf<MyCustomSmartPointer>(InRange(1, 3)));
}

// TODO(b/277974548): Add support for NonNull(SmartPointerOf(...)).
// TEST(SmartPointerOf, ValidationRejectsInvalidValue) {
//   absl::BitGen bitgen;

//   auto domain_a = NonNull(UniquePtrOf(InRange(0, 9)));
//   auto domain_b = NonNull(UniquePtrOf(InRange(10, 19)));

//   Value value_a(domain_a, bitgen);
//   Value value_b(domain_b, bitgen);

//   ASSERT_TRUE(domain_a.ValidateCorpusValue(value_a.corpus_value));
//   ASSERT_TRUE(domain_b.ValidateCorpusValue(value_b.corpus_value));

//   EXPECT_FALSE(domain_a.ValidateCorpusValue(value_b.corpus_value));
//   EXPECT_FALSE(domain_b.ValidateCorpusValue(value_a.corpus_value));
// }

}  // namespace
}  // namespace fuzztest
