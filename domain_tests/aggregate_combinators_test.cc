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

// Tests of StructOf, ConstructorOf, VariantOf and OptionalOf.

#include <cstdint>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "absl/types/variant.h"
#include "./fuzztest/domain_core.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest {
namespace {

using ::testing::_;
using ::testing::AllOf;
using ::testing::AnyOf;
using ::testing::Contains;
using ::testing::Optional;
using ::testing::UnorderedElementsAre;
using ::testing::VariantWith;

struct MyStruct {
  int a;
  std::string s;

  friend bool operator==(const MyStruct& lhs, const MyStruct& rhs) {
    return lhs.a == rhs.a && lhs.s == rhs.s;
  }
};

TEST(StructOf, InitGeneratesValidValues) {
  auto domain =
      StructOf<MyStruct>(ElementOf({5, 10}), Arbitrary<std::string>());
  absl::BitGen bitgen;
  Set<int> field_a;
  Set<std::string> field_s;
  while (field_a.size() < 2 && field_s.size() < 10) {
    auto agg = Value(domain, bitgen).user_value;
    EXPECT_THAT(agg.a, AnyOf(5, 10));
    field_a.insert(agg.a);
    field_s.insert(agg.s);
  }
}

TEST(StructOf, InitGeneratesSeeds) {
  auto domain = StructOf<MyStruct>(ElementOf({5, 10}), Arbitrary<std::string>())
                    .WithSeeds({MyStruct{5, "Five"}, MyStruct{10, "Ten"}});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              AllOf(Contains(Value(domain, MyStruct{5, "Five"})),
                    Contains(Value(domain, MyStruct{10, "Ten"}))));
}

TEST(StructOf, MutateGeneratesValidValues) {
  auto domain =
      StructOf<MyStruct>(ElementOf({5, 10}), Arbitrary<std::string>());
  absl::BitGen bitgen;
  Set<int> field_a;
  Set<std::string> field_s;
  Value agg(domain, bitgen);
  while (field_a.size() < 2 && field_s.size() < 10) {
    agg.Mutate(domain, bitgen, {}, false);
    EXPECT_THAT(agg.user_value.a, AnyOf(5, 10));
    field_a.insert(agg.user_value.a);
    field_s.insert(agg.user_value.s);
  }
}

TEST(StructOf, WorksWithStructWithUpTo16Fields) {
  struct Agg16 {
    uint32_t a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p;
    uint32_t sum() {
      return a + b + c + d + e + f + g + h + i + j + k + l + m + n + o + p;
    }
  };
  auto a = Arbitrary<uint32_t>();
  absl::BitGen bitgen;

  // Just check that we can create and mutate the value.
  auto domain = StructOf<Agg16>(a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a);
  Value value(domain, bitgen);
  const uint32_t initial_sum = value.user_value.sum();
  while (value.user_value.sum() == initial_sum) {
    value.Mutate(domain, bitgen, {}, false);
  }
  // Check that shrinking works too.
  while (value.user_value.sum() != 0) {
    value.Mutate(domain, bitgen, {}, true);
  }
}

class MyClass {
 public:
  MyClass(int a, double d, std::string s) : a_(a), d_(d), s_(std::move(s)) {}

  int a() const { return a_; }
  double d() const { return d_; }
  std::string s() const { return s_; }

 private:
  int a_;
  double d_;
  std::string s_;
};

TEST(ConstructorOf, InitGeneratesValidValues) {
  auto domain = ConstructorOf<MyClass>(ElementOf({5, 10}), Arbitrary<double>(),
                                       Arbitrary<std::string>());
  absl::BitGen bitgen;
  Set<int> field_a;
  Set<double> field_d;
  Set<std::string> field_s;
  while (field_a.size() < 2 && field_d.size() < 10 && field_s.size() < 10) {
    auto agg = Value(domain, bitgen).user_value;
    EXPECT_THAT(agg.a(), AnyOf(5, 10));
    field_a.insert(agg.a());
    field_d.insert(agg.d());
    field_s.insert(agg.s());
  }
}

TEST(ConstructorOf, MutateGeneratesValidValues) {
  auto domain = ConstructorOf<MyClass>(ElementOf({5, 10}), Arbitrary<double>(),
                                       Arbitrary<std::string>());
  absl::BitGen bitgen;
  Set<int> field_a;
  Set<double> field_d;
  Set<std::string> field_s;
  Value agg(domain, bitgen);
  while (field_a.size() < 2 && field_d.size() < 10 && field_s.size() < 10) {
    agg.Mutate(domain, bitgen, {}, false);
    EXPECT_THAT(agg.user_value.a(), AnyOf(5, 10));
    field_a.insert(agg.user_value.a());
    field_d.insert(agg.user_value.d());
    field_s.insert(agg.user_value.s());
  }
}

class HasTemplatedConstructor {
 public:
  template <typename... Args>
  HasTemplatedConstructor(Args... args) {
    sum_ = (args + ...);
  }
  int sum() const { return sum_; }

 private:
  int sum_;
};

TEST(ConstructorOf, WorksWithTemplatedConstructors) {
  auto a = Arbitrary<uint32_t>();
  absl::BitGen bitgen;

  // Just check that we can create and mutate the value.
  auto domain = ConstructorOf<HasTemplatedConstructor>(a, a, a, a, a, a, a, a,
                                                       a, a, a, a, a, a, a, a);
  Value value(domain, bitgen);
  const uint32_t initial_sum = value.user_value.sum();
  while (value.user_value.sum() == initial_sum) {
    value.Mutate(domain, bitgen, {}, false);
  }
  // Check that shrinking works too.
  while (value.user_value.sum() != 0) {
    value.Mutate(domain, bitgen, {}, true);
  }
}

struct StringMover {
  explicit StringMover(std::string&& v) : data_(std::move(v)) {}
  std::string data_;
};

TEST(ConstructorOf, WorksWithMoveConstructors) {
  auto domain = ConstructorOf<StringMover>(Arbitrary<std::string>());
  absl::BitGen bitgen;

  Value value(domain, bitgen);
  const std::string initial_value = value.user_value.data_;
  while (value.user_value.data_ == initial_value) {
    value.Mutate(domain, bitgen, {}, false);
  }
}

TEST(VariantOf, InitGenerateValidValues) {
  using X = std::variant<int, int, std::string>;
  Domain<X> domain =
      VariantOf(ElementOf({5, 10}), InRange(50, 500), PrintableAsciiString());
  absl::BitGen bitgen;
  std::vector<absl::flat_hash_set<int>> int_unique_value_arr(2);
  absl::flat_hash_set<std::string> string_unique_values;
  constexpr int n = 20;
  while (int_unique_value_arr[0].size() < 2 ||
         int_unique_value_arr[1].size() < n ||
         string_unique_values.size() < n) {
    X value = Value(domain, bitgen).user_value;
    if (value.index() == 0) {
      int val = std::get<0>(value);
      EXPECT_THAT(val, AnyOf(5, 10));
      int_unique_value_arr[0].insert(val);
    } else if (value.index() == 1) {
      int val = std::get<1>(value);
      EXPECT_LE(val, 500);
      EXPECT_GE(val, 50);
      int_unique_value_arr[1].insert(val);
    } else {
      string_unique_values.insert(std::get<2>(value));
    }
  }
}

TEST(VariantOf, InitGeneratesSeeds) {
  using X = std::variant<int, std::string>;
  Domain<X> domain = VariantOf(Arbitrary<int>(), PrintableAsciiString())
                         .WithSeeds({X{42}, X{"Hello"}});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              AllOf(Contains(Value(domain, X{42})),
                    Contains(Value(domain, X{"Hello"}))));
}

TEST(VariantOf, MutateGenerateValidValues) {
  using X = std::variant<int, int, std::string, std::vector<int>>;
  Domain<X> domain =
      VariantOf(ElementOf({5, 10}), InRange(200, 500), PrintableAsciiString(),
                ContainerOf<std::vector<int>>(InRange(1, 7)));
  absl::BitGen bitgen;
  std::vector<int> counter(4, 0);
  absl::flat_hash_set<int> unique_values[2];
  constexpr int n = 20;
  Value value(domain, bitgen);
  while (unique_values[0].size() < 2 || unique_values[1].size() < n ||
         counter[2] < n || counter[3] < n) {
    value.Mutate(domain, bitgen, {}, false);
    if (value.user_value.index() == 0) {
      int val = std::get<0>(value.user_value);
      EXPECT_THAT(val, AnyOf(5, 10));
      unique_values[0].insert(val);
    } else if (value.user_value.index() == 1) {
      int val = std::get<1>(value.user_value);
      EXPECT_LE(val, 500);
      EXPECT_GE(val, 200);
      unique_values[1].insert(val);
    }
    ++counter[value.user_value.index()];
  }
}

TEST(VariantOf, WorksWithACustomVariantType) {
  auto domain = VariantOf<absl::variant<int, double>>(Arbitrary<int>(),
                                                      Arbitrary<double>());
  absl::BitGen bitgen;
  absl::variant<int, double> v = Value(domain, bitgen).user_value;
  EXPECT_THAT(v, AnyOf(VariantWith<int>(_), VariantWith<double>(_)));
}

struct Alternative1 {};

struct Alternative2 {
  int64_t value;
};

TEST(VariantOf, WorksWithStructInnerDomain) {
  auto domain = VariantOf(StructOf<Alternative1>(),
                          StructOf<Alternative2>(Arbitrary<int64_t>()));
  absl::BitGen bitgen;
  absl::variant<Alternative1, Alternative2> v =
      Value(domain, bitgen).user_value;
  EXPECT_THAT(
      v, AnyOf(VariantWith<Alternative1>(_), VariantWith<Alternative2>(_)));
}

TEST(VariantOf, ValidationRejectsInvalidValue) {
  absl::BitGen bitgen;

  auto domain_a = VariantOf(InRange(0, 9), InRange(0.4, 9.1));
  auto domain_b = VariantOf(InRange(10, 19), InRange(11.4, 19.1));

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(
      domain_a.ValidateCorpusValue(value_b.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value for variant domain >> The value .+ is not InRange\(.+\))")));
  EXPECT_THAT(
      domain_b.ValidateCorpusValue(value_a.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value for variant domain >> The value .+ is not InRange\(.+\))")));
}

TEST(OptionalOf, InitCanMakeValuesOrNull) {
  auto domain = OptionalOf(InRange(1, 3));
  Set<std::optional<int>> values;
  absl::BitGen bitgen;
  while (values.size() < 4) {
    values.insert(Value(domain, bitgen).user_value);
  }
  EXPECT_THAT(values, UnorderedElementsAre(std::nullopt, Optional(1),
                                           Optional(2), Optional(3)));
}

TEST(OptionalOf, InitGeneratesSeeds) {
  auto domain = OptionalOf(Arbitrary<int>())
                    .WithSeeds({std::optional{7}, std::optional{42}});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              AllOf(Contains(Value(domain, std::optional{7})),
                    Contains(Value(domain, std::optional{42}))));
}

TEST(OptionalOf, MutateCanMakeValuesOrNull) {
  auto domain = OptionalOf(InRange(1, 3));
  Set<std::optional<int>> values;
  absl::BitGen bitgen;
  Value value(domain, bitgen);
  while (values.size() < 4) {
    value.Mutate(domain, bitgen, {}, false);
    values.insert(value.user_value);
  }
  EXPECT_THAT(values, UnorderedElementsAre(std::nullopt, Optional(1),
                                           Optional(2), Optional(3)));
}

TEST(OptionalOf, WorksWithACustomOptionalType) {
  auto domain = OptionalOf<absl::optional<int>>(InRange(1, 3));
  absl::BitGen bitgen;
  absl::optional<int> v = Value(domain, bitgen).user_value;
  EXPECT_THAT(v, AnyOf(absl::nullopt, Optional(_)));
}

TEST(OptionalOf, AlwaysGenerateNulloptWhenPolicySet) {
  auto domain = NullOpt<int>();

  absl::BitGen bitgen;

  Value value(domain, bitgen);
  for (int i = 0; i < 10000; ++i) {
    EXPECT_TRUE(value == std::nullopt) << "Didn't expect non-null value!";
    value.Mutate(domain, bitgen, {}, false);
  }
}

TEST(OptionalOf, DoesntGenerateNulloptWhenPolicySet) {
  auto domain = NonNull(OptionalOf(Arbitrary<int>()));

  absl::BitGen bitgen;

  Value value(domain, bitgen);
  for (int i = 0; i < 10000; ++i) {
    EXPECT_TRUE(value != std::nullopt) << "Didn't expect null value!";
    value.Mutate(domain, bitgen, {}, false);
  }
}

TEST(OptionalOf, ValidationRejectsNullValueWhenPolicySetToAlwaysSet) {
  auto domain = NonNull(OptionalOf(Arbitrary<int>()));
  auto corpus_value = domain.FromValue(std::nullopt);
  EXPECT_THAT(domain.ValidateCorpusValue(*corpus_value),
              IsInvalid("Optional value must be set"));
}

TEST(OptionalOf, ValidationRejectsInvalidNullness) {
  absl::BitGen bitgen;

  auto domain_a = NonNull(OptionalOf(Arbitrary<int>()));
  auto domain_b = NullOpt<int>();

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(domain_a.ValidateCorpusValue(value_b.corpus_value),
              IsInvalid("Optional value must be set"));
  EXPECT_THAT(domain_b.ValidateCorpusValue(value_a.corpus_value),
              IsInvalid("Optional value must be null"));
}

TEST(OptionalOf, ValidationRejectsInvalidInnerValue) {
  absl::BitGen bitgen;

  auto domain_a = NonNull(OptionalOf(InRange(0, 9)));
  auto domain_b = NonNull(OptionalOf(InRange(10, 19)));

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(
      domain_a.ValidateCorpusValue(value_b.corpus_value),
      IsInvalid(testing::MatchesRegex(R"(The value .+ is not InRange\(.+\))")));
  EXPECT_THAT(
      domain_b.ValidateCorpusValue(value_a.corpus_value),
      IsInvalid(testing::MatchesRegex(R"(The value .+ is not InRange\(.+\))")));
}

TEST(TupleOf, ValidationRejectsInvalidInnerValue) {
  absl::BitGen bitgen;

  auto domain_a = TupleOf(Arbitrary<int>(), InRange(0, 9));
  auto domain_b = TupleOf(Arbitrary<int>(), InRange(10, 99));

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(
      domain_a.ValidateCorpusValue(value_b.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value in aggregate >> The value .+ is not InRange\(.+\))")));
  EXPECT_THAT(
      domain_b.ValidateCorpusValue(value_a.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value in aggregate >> The value .+ is not InRange\(.+\))")));
}

TEST(TupleOf, DomainWithCustomPairCorpusType) {
  class DomainWithCustomPairCorpusType
      : public fuzztest::domain_implementor::DomainBase<
            DomainWithCustomPairCorpusType, std::pair<uint8_t, uint8_t>,
            std::pair<uint64_t, uint64_t>> {
   public:
    using corpus_type = DomainWithCustomPairCorpusType::DomainBase::corpus_type;
    using value_type = DomainWithCustomPairCorpusType::DomainBase::value_type;

    corpus_type Init(absl::BitGenRef prng) { return {0, 0}; }

    void Mutate(corpus_type& val, absl::BitGenRef prng,
                const domain_implementor::MutationMetadata& metadata,
                bool only_shrink) {}

    absl::Status ValidateCorpusValue(const corpus_type& value) const {
      return absl::OkStatus();
    }

    auto GetPrinter() const { return internal::UnknownPrinter(); }

    value_type GetValue(const corpus_type& v) const { return value_type(v); }

    std::optional<corpus_type> FromValue(const value_type& v) const {
      return corpus_type(v);
    }

    std::optional<corpus_type> ParseCorpus(
        const internal::IRObject& obj) const {
      return corpus_type{};
    }

    internal::IRObject SerializeCorpus(const corpus_type& v) const {
      return internal::IRObject{};
    }
  };

  auto domain = TupleOf(DomainWithCustomPairCorpusType{});
  std::tuple<std::pair<uint8_t, uint8_t>> value{{1, 2}};
  auto optional_corpus_tuple = domain.FromValue(value);
  EXPECT_TRUE(optional_corpus_tuple.has_value());
}

}  // namespace
}  // namespace fuzztest
