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

// Tests of Arbitrary<T> domains.

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/time/time.h"
#include "./fuzztest/domain.h"  // IWYU pragma: keep
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/domains/absl_helpers.h"
#include "./fuzztest/internal/domains/container_mutation_helpers.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/test_protobuf.pb.h"
#include "./fuzztest/internal/type_support.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/util/message_differencer.h"

namespace fuzztest {
namespace {

using ::fuzztest::internal::ProtoExtender;
using ::fuzztest::internal::TestProtobuf;
using ::fuzztest::internal::TestProtobuf_Enum;
using ::fuzztest::internal::TestProtobufWithExtension;
using ::fuzztest::internal::TestProtobufWithRequired;
using ::fuzztest::internal::TestSubProtobuf;
using ::google::protobuf::FieldDescriptor;
using ::testing::Contains;
using ::testing::Each;
using ::testing::ElementsAre;
using ::testing::Ge;
using ::testing::Gt;
using ::testing::IsEmpty;
using ::testing::IsTrue;
using ::testing::ResultOf;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAre;

TEST(BoolTest, Arbitrary) {
  absl::BitGen bitgen;
  Domain<bool> domain = Arbitrary<bool>();
  bool found[2]{};
  for (int i = 0; i < 20; ++i) {
    found[Value(domain, bitgen).user_value] = true;
  }
  ASSERT_THAT(found, Each(true));

  Value b(domain, bitgen);
  bool copy = b.user_value;
  b.Mutate(domain, bitgen, false);
  EXPECT_NE(b.user_value, copy);
  b.Mutate(domain, bitgen, false);
  EXPECT_EQ(b.user_value, copy);
}

TEST(ArbitraryBoolTest, InitGeneratesSeeds) {
  Domain<bool> domain = Arbitrary<bool>().WithSeeds({true});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, true))
                  // Since there are only two possible values, the seed will
                  // surely appear at least once. To make the test meaningful,
                  // we expect to see it much more often than the other value.
                  .Times(Ge(650)));
}

TEST(ArbitraryByteTest, RepeatedMutationYieldsEveryValue) {
  Domain<std::byte> domain = Arbitrary<std::byte>();
  // Verify every value appears.
  auto values = MutateUntilFoundN(domain, 256);
  VerifyRoundTripThroughConversion(values, domain);
  EXPECT_EQ(values.size(), 256);
}

TEST(ArbitraryByteTest, InitGeneratesSeeds) {
  auto domain = Arbitrary<std::byte>().WithSeeds({std::byte{42}});

  // With a 1000 tries, it's likely that any specific value will show up. To
  // make this test meaningful, we expect to see the seed many more times than
  // in a uniform distribution.
  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, std::byte{42})).Times(Ge(350)));
}

struct MyStruct {
  int a;
  std::string s;

  // These are for the tests below that try to get N distinct values.
  friend bool operator==(const MyStruct& lhs, const MyStruct& rhs) {
    return std::tie(lhs.a, lhs.s) == std::tie(rhs.a, rhs.s);
  }
  [[maybe_unused]] friend bool operator!=(const MyStruct& lhs,
                                          const MyStruct& rhs) {
    return !(lhs == rhs);
  }
  template <typename H>
  friend H AbslHashValue(H state, const MyStruct& v) {
    return H::combine(std::move(state), v.a, v.s);
  }
};

template <typename T>
class CompoundTypeTest : public testing::Test {};

// TODO(sbenzaquen): Consider supporting Abseil types directly on Arbitrary<>.
using CompoundTypeTypes =
    testing::Types<std::pair<int, std::string>, std::tuple<int>,
                   std::tuple<bool, int, std::string>, std::array<int, 1>,
                   std::array<int, 100>, std::variant<int, bool>,
                   std::optional<int>, std::unique_ptr<std::string>, MyStruct,
                   std::vector<bool>>;

TYPED_TEST_SUITE(CompoundTypeTest, CompoundTypeTypes);

TYPED_TEST(CompoundTypeTest, Arbitrary) {
  Domain<TypeParam> domain = Arbitrary<TypeParam>();
  auto values = MutateUntilFoundN(domain, 100);
  VerifyRoundTripThroughConversion(values, domain);
  // Just make sure we can find 100 different objects.
  // No need to look into their actual values.
  EXPECT_EQ(values.size(), 100);
}

TYPED_TEST(CompoundTypeTest, InitGeneratesSeeds) {
  // Seed cannot be a move-only type like std::unique_ptr<std::string>.
  if constexpr (std::is_copy_constructible_v<TypeParam>) {
    auto domain = Arbitrary<TypeParam>();
    absl::BitGen bitgen;
    auto seed = Value(domain, bitgen);
    seed.RandomizeByRepeatedMutation(domain, bitgen);
    domain.WithSeeds({seed.user_value});

    EXPECT_THAT(GenerateInitialValues(domain, 1000), Contains(seed));
  }
}

template <typename T>
class MonostateTypeTest : public testing::Test {};

using MonostateTypeTypes = testing::Types<std::true_type, std::false_type,
                                          std::array<int, 0>, std::tuple<>>;

TYPED_TEST_SUITE(MonostateTypeTest, MonostateTypeTypes);

TYPED_TEST(MonostateTypeTest, Arbitrary) {
  absl::BitGen bitgen;
  // Minimal check that Arbitrary<T> works for monostate types.
  Domain<TypeParam> domain = Arbitrary<TypeParam>();
  // Init returns a value.
  auto v = domain.Init(bitgen);
  // Mutate "works". That is, it returns.
  // We don't expect it to do anything else since the value can't be changed.
  domain.Mutate(v, bitgen, false);
}

struct BinaryTree {
  int i;
  std::unique_ptr<BinaryTree> lhs;
  std::unique_ptr<BinaryTree> rhs;

  int count_nodes() const {
    return 1 + (lhs ? lhs->count_nodes() : 0) + (rhs ? rhs->count_nodes() : 0);
  }
};

TEST(UserDefinedAggregate, NestedArbitrary) {
  auto domain = Arbitrary<BinaryTree>();
  absl::BitGen bitgen;

  Value v(domain, bitgen);
  Set<int> s;
  while (s.size() < 10) {
    s.insert(v.user_value.count_nodes());
    v.Mutate(domain, bitgen, false);
  }
}

struct StatefulIncrementDomain
    : public internal::DomainBase<StatefulIncrementDomain, int,
                                  // Just to make sure we don't mix value_type
                                  // with corpus_type
                                  std::tuple<int>> {
  corpus_type Init(absl::BitGenRef prng) {
    // Minimal code to exercise prng.
    corpus_type result = {absl::Uniform<value_type>(prng, i, i + 1)};
    ++i;
    return result;
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    std::get<0>(val) += absl::Uniform<value_type>(prng, 5, 6) +
                        static_cast<value_type>(only_shrink);
  }

  value_type GetValue(corpus_type v) const { return std::get<0>(v); }
  std::optional<corpus_type> FromValue(value_type v) const {
    return std::tuple{v};
  }

  std::optional<corpus_type> ParseCorpus(const internal::IRObject& obj) const {
    return obj.ToCorpus<corpus_type>();
  }

  internal::IRObject SerializeCorpus(const corpus_type& v) const {
    return internal::IRObject::FromCorpus(v);
  }

  absl::Status ValidateCorpusValue(const corpus_type&) const {
    return absl::OkStatus();
  }

  auto GetPrinter() const { return internal::IntegralPrinter{}; }

  value_type i = 0;
};

TEST(Domain, Constructability) {
  EXPECT_TRUE(
      (std::is_constructible_v<Domain<int>, internal::ArbitraryImpl<int>>));
  // Wrong type
  EXPECT_FALSE(
      (std::is_constructible_v<Domain<int>, internal::ArbitraryImpl<char>>));
  struct NoBase {};
  EXPECT_FALSE((std::is_constructible_v<Domain<int>, NoBase>));
}

TEST(Domain, BasicVerify) {
  Domain<int> domain = StatefulIncrementDomain{};

  absl::BitGen bitgen;

  EXPECT_EQ(Value(domain, bitgen), 0);
  EXPECT_EQ(Value(domain, bitgen), 1);

  Domain<int> copy = domain;
  EXPECT_EQ(Value(domain, bitgen), 2);
  EXPECT_EQ(Value(domain, bitgen), 3);
  // `copy` has its own state.
  EXPECT_EQ(Value(copy, bitgen), 2);
  domain = copy;
  EXPECT_EQ(Value(domain, bitgen), 3);
  EXPECT_EQ(Value(copy, bitgen), 3);

  Value i(domain, bitgen);
  Value j = i;
  i.Mutate(domain, bitgen, false);
  EXPECT_THAT(i.user_value, j.user_value + 5);
  i.Mutate(domain, bitgen, true);
  EXPECT_THAT(i.user_value, j.user_value + 11);
}

TEST(ArbitraryProtocolBufferTest, InitGeneratesSeeds) {
  TestProtobuf seed;
  seed.set_i32(42);
  seed.set_str("Hello");

  EXPECT_THAT(GenerateInitialValues(Arbitrary<TestProtobuf>().WithSeeds({seed}),
                                    1000),
              Contains(ResultOf(
                  [&seed](const auto& val) {
                    return google::protobuf::util::MessageDifferencer::Equals(
                        val.user_value, seed);
                  },
                  IsTrue())));
}

// TODO(b/246448769): Rewrite the test to decrease the chance of failure.
TEST(ProtocolBuffer,
     RepeatedMutationEventuallyMutatesAllFieldsOfArbitraryProtobuf) {
  Domain<TestProtobuf> domain = Arbitrary<TestProtobuf>();

  absl::BitGen bitgen;
  Value val(domain, bitgen);

  const auto verify_field_changes = [&](std::string_view name, auto has,
                                        auto get) {
    const auto optional_get = [&]() {
      return has(val.user_value) ? std::optional(get(val.user_value))
                                 : std::nullopt;
    };
    using OptionalV = decltype(optional_get());
    Set<OptionalV> values;

    int iterations = 10'000;
    while (--iterations > 0 && values.size() < 2) {
      values.insert(optional_get());
      val.Mutate(domain, bitgen, false);
    }
    EXPECT_GT(iterations, 0)
        << "Field: " << name << " -- " << testing::PrintToString(values);
  };

  const auto verify_repeated_field_changes = [&](std::string_view name,
                                                 auto get) {
    Set<int> sizes;
    Set<std::decay_t<decltype(get(val.user_value)[0])>> elem0;

    int iterations = 10'000;
    while (--iterations > 0 && (elem0.size() < 2 || sizes.size() < 2)) {
      auto field = get(val.user_value);
      sizes.insert(field.size());
      if (field.size() > 0) {
        elem0.insert(field[0]);
      }
      val.Mutate(domain, bitgen, false);
    }
    EXPECT_GT(iterations, 0)
        << "Field: " << name << " -- " << testing::PrintToString(sizes)
        << " ++ " << testing::PrintToString(elem0);
  };

  VisitTestProtobuf(verify_field_changes, verify_repeated_field_changes);

  VerifyRoundTripThroughConversion(val, domain);
}

TEST(ProtocolBuffer, RepeatedMutationEventuallyMutatesExtensionFields) {
  auto has_ext = ResultOf(
      [](const auto& val) {
        return val.user_value.HasExtension(internal::ProtoExtender::ext);
      },
      IsTrue());
  auto has_rep_ext = ResultOf(
      [](const auto& val) {
        return val.user_value.ExtensionSize(internal::ProtoExtender::rep_ext);
      },
      Gt(0));
  EXPECT_THAT(
      GenerateNonUniqueValues(Arbitrary<TestProtobufWithExtension>(), 1, 5000),
      AllOf(Contains(has_ext), Contains(has_rep_ext)));
}

// TODO(b/246652379): Re-enable after b/231212420 is fixed.
TEST(ProtocolBuffer,
     DISABLED_ShrinkingEventuallyUnsetsAndEmptiesAllFieldsOfArbitraryProtobuf) {
  Domain<TestProtobuf> domain = Arbitrary<TestProtobuf>();

  absl::BitGen bitgen;
  Value val(domain, bitgen);

  for (int i = 0; i < 10'000; ++i) {
    val.Mutate(domain, bitgen, /*only_shrink=*/false);
  }

  // We verify that the object actually has things in it. This can technically
  // fail if the very last operation done above was to unset the very last set
  // field, but it is very unlikely.
  ASSERT_NE(val.user_value.ByteSizeLong(), 0);

  // ByteSizeLong() == 0 is a simple way to determine that all fields are unset.
  for (int iteration = 0;
       val.user_value.ByteSizeLong() > 0 && iteration < 50'000; ++iteration) {
    const auto prev = val;
    val.Mutate(domain, bitgen, /*only_shrink=*/true);
    ASSERT_TRUE(TowardsZero(prev.user_value, val.user_value))
        << prev << " -vs- " << val;
  }
  EXPECT_EQ(val.user_value.ByteSizeLong(), 0);
}

TEST(ProtocolBufferWithRequiredFields, OptionalFieldIsEventuallySet) {
  auto domain = Arbitrary<TestProtobufWithRequired>()
                    .WithRepeatedFieldsMaxSize(0)
                    .WithProtobufFieldUnset("sub_req");
  absl::BitGen bitgen;
  Value val(domain, bitgen);

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();

  for (int i = 0; i < 1000; ++i) {
    val.Mutate(domain, bitgen, false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();
    if (val.user_value.has_i32()) break;
  }

  EXPECT_TRUE(val.user_value.has_i32());
}

TEST(ProtocolBufferWithRequiredFields, OptionalFieldIsEventuallyUnset) {
  auto domain = Arbitrary<TestProtobufWithRequired>()
                    .WithRepeatedFieldsMaxSize(0)
                    .WithProtobufFieldUnset("sub_req");
  absl::BitGen bitgen;
  Value val(domain, bitgen);

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();

  // With the restricted domain, the probability of unsetting the field i32 is
  // at least 1/800. Hence, within 11000 iterations we'll fail to observe this
  // event with probability at most 10^(-6).
  for (int i = 0; i < 11000; ++i) {
    val.Mutate(domain, bitgen, false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();
    if (!val.user_value.has_i32()) break;
  }

  EXPECT_FALSE(val.user_value.has_i32());
}

TEST(ProtocolBufferWithRequiredFields, OptionalFieldInSubprotoIsEventuallySet) {
  auto domain = Arbitrary<TestProtobufWithRequired>()
                    .WithRepeatedFieldsMaxSize(0)
                    .WithProtobufFieldUnset("sub_req");
  absl::BitGen bitgen;
  Value val(domain, bitgen);

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();

  for (int i = 0; i < 1000; ++i) {
    val.Mutate(domain, bitgen, false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();
    if (val.user_value.has_req_sub() &&
        val.user_value.req_sub().has_subproto_i32())
      break;
  }

  EXPECT_TRUE(val.user_value.has_req_sub() &&
              val.user_value.req_sub().has_subproto_i32());
}

TEST(ProtocolBufferWithRequiredFields,
     OptionalFieldInSubprotoIsEventuallyUnset) {
  auto domain = Arbitrary<TestProtobufWithRequired>()
                    .WithRepeatedFieldsMaxSize(0)
                    .WithProtobufFieldUnset("sub_req");
  absl::BitGen bitgen;
  Value val(domain, bitgen);

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();

  // With the restricted domain, the probability of unsetting the field
  // req_sub.subproto_i32 is at least 1/800. Hence, within 11000 iterations
  // we'll fail to observe this event with probability at most 10^(-6).
  for (int i = 0; i < 11000; ++i) {
    val.Mutate(domain, bitgen, false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();
    if (val.user_value.has_req_sub() &&
        !val.user_value.req_sub().has_subproto_i32())
      break;
  }

  EXPECT_TRUE(val.user_value.has_req_sub() &&
              !val.user_value.req_sub().has_subproto_i32());
}

bool IsTestProtobufWithRequired(const FieldDescriptor* field) {
  return field->message_type()->full_name() ==
         "fuzztest.internal.TestProtobufWithRequired";
}

TEST(ProtocolBufferWithRequiredFields,
     OptionalFieldWithRequiredFieldsIsEventuallySet) {
  auto domain =
      Arbitrary<TestProtobufWithRequired>()
          .WithRepeatedFieldsMaxSize(0)
          .WithProtobufFields(IsTestProtobufWithRequired,
                              Arbitrary<TestProtobufWithRequired>()
                                  .WithRepeatedFieldsMaxSize(0)
                                  // Disallow recursive nesting beyond depth 1.
                                  .WithProtobufFieldUnset("sub_req"));
  absl::BitGen bitgen;
  Value val(domain, bitgen);

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();

  for (int i = 0; i < 1000; ++i) {
    val.Mutate(domain, bitgen, false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();
    if (val.user_value.has_sub_req()) {
      ASSERT_TRUE(val.user_value.sub_req().IsInitialized())
          << val.user_value.DebugString();
      break;
    }
  }

  EXPECT_TRUE(val.user_value.has_sub_req());
}

TEST(ProtocolBufferWithRequiredFields, MapFieldIsEventuallyPopulated) {
  auto domain =
      Arbitrary<TestProtobufWithRequired>()
          .WithRepeatedFieldsMaxSize(1)
          .WithProtobufFields(IsTestProtobufWithRequired,
                              Arbitrary<TestProtobufWithRequired>()
                                  .WithRepeatedFieldsMaxSize(0)
                                  // Disallow recursive nesting beyond depth 1.
                                  .WithProtobufFieldUnset("sub_req"));
  absl::BitGen bitgen;
  Value val(domain, bitgen);

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();

  bool found = false;
  for (int i = 0; i < 1000 && !found; ++i) {
    val.Mutate(domain, bitgen, false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();
    for (const auto& pair : val.user_value.map_sub_req()) {
      found = true;
      ASSERT_TRUE(pair.second.IsInitialized()) << pair.second.DebugString();
    }
  }

  EXPECT_TRUE(found);
}

TEST(ProtocolBufferWithRequiredFields, ShrinkingNeverRemovesRequiredFields) {
  auto domain =
      Arbitrary<TestProtobufWithRequired>()
          .WithRepeatedFieldsMaxSize(1)
          .WithProtobufFields(IsTestProtobufWithRequired,
                              Arbitrary<TestProtobufWithRequired>()
                                  .WithRepeatedFieldsMaxSize(0)
                                  // Disallow recursive nesting beyond depth 1.
                                  .WithProtobufFieldUnset("sub_req"));
  absl::BitGen bitgen;
  Value val(domain, bitgen);

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();

  for (int i = 0; i < 1000; ++i) {
    val.Mutate(domain, bitgen, /*only_shrink=*/false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();
  }

  const auto is_minimal = [](const auto& v) {
    return !v.has_i32() && v.req_i32() == 0 && v.req_e() == 0 &&
           !v.req_sub().has_subproto_i32() &&
           v.req_sub().subproto_rep_i32().empty() && !v.has_sub_req();
  };

  while (!is_minimal(val.user_value)) {
    val.Mutate(domain, bitgen, /*only_shrink=*/true);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();
  }
}

TEST(ProtocolBuffer, CanUsePerFieldDomains) {
  Domain<TestProtobuf> domain =
      Arbitrary<TestProtobuf>()
          .WithInt32Field("i32", InRange(1, 4))
          .WithStringField("str", PrintableAsciiString().WithSize(4))
          .WithEnumField(
              "e", ElementOf<int>({TestProtobuf::Label2, TestProtobuf::Label4}))
          .WithRepeatedBoolField("rep_b", VectorOf(Just(true)).WithSize(2))
          .WithProtobufField("subproto",
                             Arbitrary<TestSubProtobuf>().WithInt32Field(
                                 "subproto_i32", Just(-1)));

  absl::BitGen bitgen;
  Value val(domain, bitgen);

  Set<int32_t> i32_values;
  Set<std::string> str_values;
  Set<TestProtobuf::Enum> e_values;
  Set<std::vector<bool>> rep_b_values;
  Set<int> subproto_i32_values;

  // InRange(1, 4) -> 4 values.
  static constexpr int i32_count = 4;
  // There are way too many possible strings, so check we find a handful.
  static constexpr int str_count = 10;
  // Only two enums in the ElementOf.
  static constexpr int e_count = 2;
  // Only one possible value: `{true, true}`.
  static constexpr int rep_p_count = 1;
  // Only one possible value: `-1`
  static constexpr int subproto_i32_count = 1;

  while (i32_values.size() < i32_count || str_values.size() < str_count ||
         e_values.size() < e_count || rep_b_values.size() < rep_p_count ||
         subproto_i32_values.size() < subproto_i32_count) {
    val.Mutate(domain, bitgen, false);
    if (val.user_value.has_i32()) i32_values.insert(val.user_value.i32());
    if (val.user_value.has_str()) str_values.insert(val.user_value.str());
    if (val.user_value.has_e()) e_values.insert(val.user_value.e());
    if (!val.user_value.rep_b().empty()) {
      rep_b_values.emplace(val.user_value.rep_b().begin(),
                           val.user_value.rep_b().end());
    }
    if (val.user_value.subproto().has_subproto_i32()) {
      subproto_i32_values.insert(val.user_value.subproto().subproto_i32());
    }

    // Let's make sure the custom corpus information can be serialized properly.
    auto parsed = domain.ParseCorpus(domain.SerializeCorpus(val.corpus_value));
    ASSERT_TRUE(parsed);
    auto value_copy = domain.GetValue(*parsed);
    EXPECT_TRUE(Eq{}(val.user_value, value_copy));
  }

  EXPECT_THAT(i32_values, UnorderedElementsAre(1, 2, 3, 4));
  EXPECT_THAT(str_values, Each(SizeIs(4)));
  EXPECT_THAT(e_values,
              UnorderedElementsAre(TestProtobuf::Label2, TestProtobuf::Label4));
  EXPECT_THAT(rep_b_values, UnorderedElementsAre(ElementsAre(true, true)));
  EXPECT_THAT(subproto_i32_values, ElementsAre(-1));
}

TEST(ProtocolBuffer, InvalidInputReportsError) {
  EXPECT_DEATH_IF_SUPPORTED(
      Arbitrary<TestProtobuf>().WithStringField("i32",
                                                Arbitrary<std::string>()),
      "Failed precondition.*"
      "does not match field `fuzztest.internal.TestProtobuf.i32`");
  EXPECT_DEATH_IF_SUPPORTED(
      Arbitrary<TestProtobuf>()
          .WithInt32Field("i32", Just(0))
          .WithInt32Field("i32", Just(0)),
      "Failed precondition.*"
      "field `fuzztest.internal.TestProtobuf.i32` has been set multiple times");
}

TEST(ProtocolBuffer, ValidationRejectsUnexpectedOptionalField) {
  TestSubProtobuf user_value;
  auto domain_with_optional_always_set =
      Arbitrary<TestSubProtobuf>().WithOptionalFieldsAlwaysSet();
  auto corpus_value = domain_with_optional_always_set.FromValue(user_value);
  EXPECT_THAT(
      domain_with_optional_always_set.ValidateCorpusValue(*corpus_value),
      IsInvalid("Invalid value for field subproto_i32 >> Optional value must "
                "be set"));

  auto domain_with_repeated_always_set =
      Arbitrary<TestSubProtobuf>().WithRepeatedFieldsAlwaysSet();
  EXPECT_THAT(domain_with_repeated_always_set.ValidateCorpusValue(
                  *domain_with_optional_always_set.FromValue(user_value)),
              IsInvalid("Invalid value for field subproto_rep_i32 >> Invalid "
                        "size: 0. Min size: 1"));
}

TEST(ProtocolBuffer, SerializeAndParseCanHandleExtensions) {
  auto domain = Arbitrary<TestProtobufWithExtension>();
  TestProtobufWithExtension user_value;
  user_value.SetExtension(ProtoExtender::ext, "Hello?!?!");
  auto corpus_value = domain.FromValue(user_value);
  EXPECT_TRUE(corpus_value != std::nullopt);
  auto serialized = domain.SerializeCorpus(corpus_value.value());
  auto parsed = domain.ParseCorpus(serialized);
  EXPECT_TRUE(parsed != std::nullopt);
  auto user_value_after_serialize_parse = domain.GetValue(parsed.value());
  EXPECT_EQ("Hello?!?!",
            user_value_after_serialize_parse.GetExtension(ProtoExtender::ext));
}

TEST(ProtocolBuffer, ValidationRejectsUnexpectedSingularField) {
  absl::BitGen bitgen;

  Domain<TestProtobuf> domain_a =
      Arbitrary<TestProtobuf>().WithInt32FieldAlwaysSet("i32", InRange(1, 4));
  Domain<TestProtobuf> domain_b =
      Arbitrary<TestProtobuf>().WithInt32FieldUnset("i32");

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(
      domain_a.ValidateCorpusValue(value_b.corpus_value),
      IsInvalid("Invalid value for field i32 >> Optional value must be set"));
  EXPECT_THAT(
      domain_b.ValidateCorpusValue(value_a.corpus_value),
      IsInvalid("Invalid value for field i32 >> Optional value must be null"));
}

TEST(ProtocolBuffer, ValidationRejectsUnexpectedSingularExtensionField) {
  absl::BitGen bitgen;

  Domain<TestProtobufWithExtension> domain_a =
      Arbitrary<TestProtobufWithExtension>().WithFieldAlwaysSet(
          "fuzztest.internal.ProtoExtender.ext");
  Domain<TestProtobufWithExtension> domain_b =
      Arbitrary<TestProtobufWithExtension>().WithStringFieldUnset(
          "fuzztest.internal.ProtoExtender.ext");

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(domain_a.ValidateCorpusValue(value_b.corpus_value),
              IsInvalid(testing::MatchesRegex(
                  R"(.* field ext .* Optional value must be set)")));
  EXPECT_THAT(domain_b.ValidateCorpusValue(value_a.corpus_value),
              IsInvalid(testing::MatchesRegex(
                  R"(.* field ext .* Optional value must be null)")));
}

TEST(ProtocolBuffer, ValidationRejectsUnexpectedRepeatedField) {
  absl::BitGen bitgen;

  Domain<TestProtobuf> domain_a =
      Arbitrary<TestProtobuf>().WithRepeatedInt32Field(
          "rep_i32", VectorOf(InRange(1, 4)).WithMinSize(1));
  Domain<TestProtobuf> domain_b =
      Arbitrary<TestProtobuf>().WithRepeatedInt32Field(
          "rep_i32", VectorOf(InRange(1, 4)).WithMaxSize(0));

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(
      domain_a.ValidateCorpusValue(value_b.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value for field rep_i32 >> Invalid size: .+. Min size: 1)")));
  EXPECT_THAT(
      domain_b.ValidateCorpusValue(value_a.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value for field rep_i32 >> Invalid size: .+. Max size: 0)")));
}

TEST(ProtocolBuffer, ValidationRejectsUnexpectedRepeatedExtensionField) {
  absl::BitGen bitgen;

  Domain<TestProtobufWithExtension> domain_a =
      Arbitrary<TestProtobufWithExtension>().WithRepeatedFieldMinSize(
          "fuzztest.internal.ProtoExtender.rep_ext", 1);
  Domain<TestProtobufWithExtension> domain_b =
      Arbitrary<TestProtobufWithExtension>().WithRepeatedFieldMaxSize(
          "fuzztest.internal.ProtoExtender.rep_ext", 0);

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(domain_a.ValidateCorpusValue(value_b.corpus_value),
              IsInvalid(testing::MatchesRegex(
                  R"(.* field rep_ext .* Invalid size: 0. Min size: 1)")));
  EXPECT_THAT(domain_b.ValidateCorpusValue(value_a.corpus_value),
              IsInvalid(testing::MatchesRegex(
                  R"(.* field rep_ext .* Invalid size: .+. Max size: 0)")));
}

TEST(ProtocolBuffer, WithFieldsAlwaysSetResetsWithMaxRepeatedFieldsSize) {
  absl::BitGen bitgen;

  Domain<TestProtobuf> domain =
      Arbitrary<TestProtobuf>()
          .WithFieldsUnset()
          .WithRepeatedFieldsMaxSize(
              [](const google::protobuf::FieldDescriptor* field) {
                return field->name() == "rep_i32";
              },
              1)
          .WithFieldsAlwaysSet();

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(ResultOf(
                  [](const Value<Domain<TestProtobuf>>& val) {
                    return val.user_value.rep_i32_size();
                  },
                  Gt(1))));
}

TEST(ProtocolBufferEnum, Arbitrary) {
  auto domain = Arbitrary<TestProtobuf_Enum>();
  absl::BitGen bitgen;
  Value val(domain, bitgen);

  Set<TestProtobuf_Enum> s;
  while (s.size() < internal::TestProtobuf_Enum_descriptor()->value_count()) {
    s.insert(val.user_value);
    val.Mutate(domain, bitgen, false);
  }
  val.Mutate(domain, bitgen, true);
}

TEST(ArbitraryProtocolBufferEnum, InitGeneratesSeeds) {
  auto domain = Arbitrary<TestProtobuf_Enum>().WithSeeds(
      {TestProtobuf_Enum::TestProtobuf_Enum_Label5});

  EXPECT_THAT(
      GenerateInitialValues(domain, 1000),
      Contains(Value(domain, TestProtobuf_Enum::TestProtobuf_Enum_Label5))
          // Since there are only 5 enum elements, the seed will surely appear
          // at least once. To make the test meaningful, we expect to see it at
          // least half the time, unlike the other 4 elements.
          .Times(Ge(500)));
}

TEST(ProtocolBuffer, CountNumberOfFieldsCorrect) {
  using T = TestProtobuf;
  using SubT = TestSubProtobuf;
  auto domain = Arbitrary<T>();
  T v;
  auto corpus_v_uninitialized = domain.FromValue(v);
  EXPECT_TRUE(corpus_v_uninitialized != std::nullopt);
  EXPECT_EQ(domain.CountNumberOfFields(corpus_v_uninitialized.value()), 26);
  v.set_allocated_subproto(new SubT());
  auto corpus_v_initizalize_one_optional_proto = domain.FromValue(v);
  EXPECT_TRUE(corpus_v_initizalize_one_optional_proto != std::nullopt);
  EXPECT_EQ(domain.CountNumberOfFields(
                corpus_v_initizalize_one_optional_proto.value()),
            28);
  v.add_rep_subproto();
  auto corpus_v_initizalize_one_repeated_proto_1 = domain.FromValue(v);
  EXPECT_TRUE(corpus_v_initizalize_one_repeated_proto_1 != std::nullopt);
  EXPECT_EQ(domain.CountNumberOfFields(
                corpus_v_initizalize_one_repeated_proto_1.value()),
            30);
  v.add_rep_subproto();
  auto corpus_v_initizalize_one_repeated_proto_2 = domain.FromValue(v);
  EXPECT_TRUE(corpus_v_initizalize_one_repeated_proto_2 != std::nullopt);
  EXPECT_EQ(domain.CountNumberOfFields(
                corpus_v_initizalize_one_repeated_proto_2.value()),
            32);
}

TEST(SequenceContainerMutation, CopyPartRejects) {
  std::string to_initial = "abcd";
  std::string to;
  std::string from = "efgh";

  // Rejects zero size of from.
  to = to_initial;
  EXPECT_FALSE(internal::CopyPart<false>(from, to, 0, 0, 4, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects invalid starting offset of from.
  to = to_initial;
  EXPECT_FALSE(internal::CopyPart<false>(from, to, 4, 1, 4, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects invalid starting offset of to.
  to = to_initial;
  EXPECT_FALSE(internal::CopyPart<false>(from, to, 3, 1, 5, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects invalid size of from.
  to = to_initial;
  EXPECT_FALSE(internal::CopyPart<false>(from, to, 0, 5, 4, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects larger than max copy.
  to = to_initial;
  EXPECT_FALSE(internal::CopyPart<false>(from, to, 0, 4, 4, 7));
  EXPECT_EQ(to, to_initial);
  // Rejects no mutation.
  to = to_initial;
  EXPECT_FALSE(internal::CopyPart<false>(to_initial, to, 0, 3, 0, 10));
  EXPECT_EQ(to, to_initial);
}

TEST(SequenceContainerMutation, CopyPartAccepts) {
  std::string to_initial = "abcd";
  std::string to;
  std::string from = "efgh";

  // Accepts and mutates.
  to = to_initial;
  EXPECT_TRUE(internal::CopyPart<false>(from, to, 0, 3, 0, 10));
  EXPECT_EQ(to, "efgd");
  to = to_initial;
  EXPECT_TRUE(internal::CopyPart<false>(from, to, 0, 4, 4, 10));
  EXPECT_EQ(to, "abcdefgh");
  to = to_initial;
  EXPECT_TRUE(internal::CopyPart<false>(from, to, 0, 4, 2, 10));
  EXPECT_EQ(to, "abefgh");

  // Accepts self-copy.
  to = to_initial;
  EXPECT_TRUE(internal::CopyPart<true>(to, to, 0, 3, 1, 10));
  EXPECT_EQ(to, "aabc");
}

TEST(SequenceContainerMutation, InsertPartRejects) {
  std::string to_initial = "abcd";
  std::string to;
  std::string from = "efgh";
  // Rejects zero size of from.
  to = to_initial;
  EXPECT_FALSE(internal::InsertPart<false>(from, to, 0, 0, 4, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects invalid starting offset of from.
  to = to_initial;
  EXPECT_FALSE(internal::InsertPart<false>(from, to, 4, 1, 4, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects invalid starting offset of to.
  to = to_initial;
  EXPECT_FALSE(internal::InsertPart<false>(from, to, 3, 1, 5, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects invalid size of from.
  to = to_initial;
  EXPECT_FALSE(internal::InsertPart<false>(from, to, 0, 5, 4, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects larger than max insertion.
  to = to_initial;
  EXPECT_FALSE(internal::InsertPart<false>(from, to, 0, 4, 4, 7));
  EXPECT_EQ(to, to_initial);
}

TEST(SequenceContainerMutation, InsertPartAccepts) {
  std::string to_initial = "abcd";
  std::string to;
  std::string from = "efgh";

  // Accepts and mutates.
  to = to_initial;
  EXPECT_TRUE(internal::InsertPart<false>(from, to, 0, 4, 0, 10));
  EXPECT_EQ(to, "efghabcd");
  to = to_initial;
  EXPECT_TRUE(internal::InsertPart<false>(from, to, 0, 4, 4, 10));
  EXPECT_EQ(to, "abcdefgh");
  to = to_initial;
  EXPECT_TRUE(internal::InsertPart<false>(from, to, 0, 4, 2, 10));
  EXPECT_EQ(to, "abefghcd");

  // Accepts self-copy.
  to = to_initial;
  EXPECT_TRUE(internal::InsertPart<true>(to, to, 0, 3, 1, 10));
  EXPECT_EQ(to, "aabcbcd");
}

// Note: this test is based on knowledge of internal representation of
// absl::Duration and will fail if the internal representation changes.
TEST(ArbitraryDurationTest, ValidatesAssumptionsAboutAbslDurationInternals) {
  absl::Duration min_positive = absl::Nanoseconds(1) / 4;
  absl::Duration max = absl::Seconds(std::numeric_limits<int64_t>::max()) +
                       (absl::Seconds(1) - min_positive);

  EXPECT_NE(absl::ZeroDuration(), min_positive);
  EXPECT_EQ(absl::ZeroDuration(), (min_positive / 2));
  EXPECT_NE(absl::InfiniteDuration(), max);
  EXPECT_EQ(absl::InfiniteDuration(), max + min_positive);
}

TEST(ArbitraryDurationTest, ValidatesMakeDurationResults) {
  EXPECT_EQ(internal::MakeDuration(0, 0), absl::ZeroDuration());
  EXPECT_EQ(internal::MakeDuration(0, 1), absl::Nanoseconds(0.25));
  EXPECT_EQ(internal::MakeDuration(0, 400'000), absl::Microseconds(100));
  EXPECT_EQ(internal::MakeDuration(1, 500'000'000), absl::Seconds(1.125));
  EXPECT_EQ(internal::MakeDuration(-50, 30), absl::Seconds(-49.9999999925));
  EXPECT_EQ(internal::MakeDuration(-1, 3'999'999'999u),
            absl::Nanoseconds(-0.25));
  EXPECT_EQ(internal::MakeDuration(-2, 3'999'999'999u),
            absl::Seconds(-1.00000000025));
}

TEST(ArbitraryDurationTest, ValidatesGetSecondsResults) {
  EXPECT_EQ(internal::GetSeconds(internal::MakeDuration(10, 20)), 10);
  EXPECT_EQ(internal::GetSeconds(internal::MakeDuration(-50, 30)), -50);
  EXPECT_EQ(internal::GetSeconds(internal::MakeDuration(
                std::numeric_limits<int64_t>::min(), 10)),
            std::numeric_limits<int64_t>::min());
  EXPECT_EQ(internal::GetSeconds(internal::MakeDuration(
                std::numeric_limits<int64_t>::max(), 10)),
            std::numeric_limits<int64_t>::max());
}

TEST(ArbitraryDurationTest, ValidatesGetTicksResults) {
  EXPECT_EQ(internal::GetTicks(internal::MakeDuration(100, 200)), 200);
  EXPECT_EQ(internal::GetTicks(internal::MakeDuration(-100, 200)), 200);
  EXPECT_EQ(internal::GetTicks(internal::MakeDuration(
                std::numeric_limits<int64_t>::min(), 3'999'999'999u)),
            3'999'999'999u);
  EXPECT_EQ(internal::GetTicks(internal::MakeDuration(
                std::numeric_limits<int64_t>::max(), 3'999'999'999u)),
            3'999'999'999u);
}

TEST(ArbitraryDurationTest, InitGeneratesSeeds) {
  Domain<absl::Duration> domain =
      Arbitrary<absl::Duration>().WithSeeds({absl::Seconds(42)});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, absl::Seconds(42))));
}

enum class DurationType {
  kInfinity,
  kMinusInfinity,
  kZero,
  kNegative,
  kPositive
};

TEST(ArbitraryDurationTest, GeneratesAllTypesOfValues) {
  absl::flat_hash_set<DurationType> to_find = {
      DurationType::kInfinity, DurationType::kMinusInfinity,
      DurationType::kZero, DurationType::kNegative, DurationType::kPositive};
  auto domain = Arbitrary<absl::Duration>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/100, /*num_mutations=*/900);
  ASSERT_THAT(values, SizeIs(Ge(1000)));

  for (const auto& val : values) {
    if (val.user_value == absl::InfiniteDuration()) {
      to_find.erase(DurationType::kInfinity);
    } else if (val.user_value == -absl::InfiniteDuration()) {
      to_find.erase(DurationType::kMinusInfinity);
    } else if (val.user_value == absl::ZeroDuration()) {
      to_find.erase(DurationType::kZero);
    } else if (val.user_value < absl::ZeroDuration()) {
      to_find.erase(DurationType::kNegative);
    } else if (val.user_value > absl::ZeroDuration()) {
      to_find.erase(DurationType::kPositive);
    }
  }
  EXPECT_THAT(to_find, IsEmpty());
}

uint64_t AbsoluteValueOf(absl::Duration d) {
  auto [secs, ticks] = internal::GetSecondsAndTicks(d);
  if (secs == std::numeric_limits<int64_t>::min()) {
    return static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1 +
           ticks;
  }
  return static_cast<uint64_t>(std::abs(secs)) + ticks;
}

TEST(ArbitraryDurationTest, ShrinksCorrectly) {
  auto domain = Arbitrary<absl::Duration>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/100, /*num_mutations=*/900);
  ASSERT_THAT(values, SizeIs(Ge(1000)));

  ASSERT_TRUE(TestShrink(
                  domain, values,
                  [](auto v) {
                    return (v == absl::InfiniteDuration() ||
                            v == -absl::InfiniteDuration() ||
                            v == absl::ZeroDuration());
                  },
                  [](auto prev, auto next) {
                    // For values other than (-)inf, next is closer to zero,
                    // so the absolute value of next is less than that of prev
                    return ((prev == absl::InfiniteDuration() &&
                             next == absl::InfiniteDuration()) ||
                            (prev == -absl::InfiniteDuration() &&
                             next == -absl::InfiniteDuration()) ||
                            AbsoluteValueOf(next) < AbsoluteValueOf(prev));
                  })
                  .ok());
}

// Checks that indirect call to Arbitrary<absl::Duration> works.
TEST(ArbitraryDurationTest, ArbitraryVectorHasAllTypesOfValues) {
  absl::flat_hash_set<DurationType> to_find = {
      DurationType::kInfinity, DurationType::kMinusInfinity,
      DurationType::kZero, DurationType::kNegative, DurationType::kPositive};
  auto domain = Arbitrary<std::vector<absl::Duration>>();
  absl::flat_hash_set<Value<decltype(domain)>> values =
      GenerateValues(domain,
                     /*num_seeds=*/100, /*num_mutations=*/900);
  ASSERT_THAT(values, SizeIs(Ge(1000)));

  for (const auto& val : values) {
    if (val.user_value.empty()) continue;
    absl::Duration d = val.user_value[0];
    if (d == absl::InfiniteDuration()) {
      to_find.erase(DurationType::kInfinity);
    } else if (d == -absl::InfiniteDuration()) {
      to_find.erase(DurationType::kMinusInfinity);
    } else if (d == absl::ZeroDuration()) {
      to_find.erase(DurationType::kZero);
    } else if (d < absl::ZeroDuration()) {
      to_find.erase(DurationType::kNegative);
    } else if (d > absl::ZeroDuration()) {
      to_find.erase(DurationType::kPositive);
    }
  }
  EXPECT_THAT(to_find, IsEmpty());
}

TEST(ArbitraryTimeTest, InitGeneratesSeeds) {
  Domain<absl::Time> domain = Arbitrary<absl::Time>().WithSeeds(
      {absl::UnixEpoch() + absl::Seconds(42)});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, absl::UnixEpoch() + absl::Seconds(42))));
}

enum class TimeType {
  kInfinitePast,
  kInfiniteFuture,
  kUnixEpoch,
  kFiniteNonEpoch
};

TEST(ArbitraryTimeTest, GeneratesAllTypesOfValues) {
  absl::flat_hash_set<TimeType> to_find = {
      TimeType::kInfinitePast, TimeType::kInfiniteFuture, TimeType::kUnixEpoch,
      TimeType::kFiniteNonEpoch};
  auto domain = Arbitrary<absl::Time>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/100, /*num_mutations=*/900);
  ASSERT_THAT(values, SizeIs(Ge(1000)));

  for (const auto& val : values) {
    if (val.user_value == absl::InfinitePast()) {
      to_find.erase(TimeType::kInfinitePast);
    } else if (val.user_value == absl::InfiniteFuture()) {
      to_find.erase(TimeType::kInfiniteFuture);
    } else if (val.user_value == absl::UnixEpoch()) {
      to_find.erase(TimeType::kUnixEpoch);
    } else {
      to_find.erase(TimeType::kFiniteNonEpoch);
    }
  }
  EXPECT_THAT(to_find, IsEmpty());
}

TEST(ArbitraryTimeTest, ShrinksCorrectly) {
  auto domain = Arbitrary<absl::Time>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/100, /*num_mutations=*/900);
  ASSERT_THAT(values, SizeIs(Ge(1000)));

  ASSERT_TRUE(TestShrink(
                  domain, values,
                  [](auto v) {
                    return (v == absl::InfinitePast() ||
                            v == absl::InfiniteFuture() ||
                            v == absl::UnixEpoch());
                  },
                  [](auto prev, auto next) {
                    // For values other than inf, next is closer to epoch
                    return ((prev == absl::InfinitePast() &&
                             next == absl::InfinitePast()) ||
                            (prev == absl::InfiniteFuture() &&
                             next == absl::InfiniteFuture()) ||
                            AbsoluteValueOf(next - absl::UnixEpoch()) <
                                AbsoluteValueOf(prev - absl::UnixEpoch()));
                  })
                  .ok());
}

// Checks that indirect call to Arbitrary<absl::Time> works.
TEST(ArbitraryTimeTest, ArbitraryVectorHasAllTypesOfValues) {
  absl::flat_hash_set<TimeType> to_find = {
      TimeType::kInfinitePast, TimeType::kInfiniteFuture, TimeType::kUnixEpoch,
      TimeType::kFiniteNonEpoch};
  auto domain = Arbitrary<std::vector<absl::Time>>();
  absl::flat_hash_set<Value<decltype(domain)>> values =
      GenerateValues(domain,
                     /*num_seeds=*/100, /*num_mutations=*/900);
  ASSERT_THAT(values, SizeIs(Ge(1000)));

  for (const auto& val : values) {
    if (val.user_value.empty()) continue;
    absl::Time t = val.user_value[0];
    if (t == absl::InfinitePast()) {
      to_find.erase(TimeType::kInfinitePast);
    } else if (t == absl::InfiniteFuture()) {
      to_find.erase(TimeType::kInfiniteFuture);
    } else if (t == absl::UnixEpoch()) {
      to_find.erase(TimeType::kUnixEpoch);
    } else {
      to_find.erase(TimeType::kFiniteNonEpoch);
    }
  }
  EXPECT_THAT(to_find, IsEmpty());
}

}  // namespace
}  // namespace fuzztest
