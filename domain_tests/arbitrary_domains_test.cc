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
#include "absl/random/random.h"
#include "./fuzztest/domain.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/domain.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/test_protobuf.pb.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest {
namespace {

using ::testing::Each;
using ::testing::ElementsAre;
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
    : public internal::DomainBase<StatefulIncrementDomain> {
  using value_type = int;
  // Just to make sure we don't mix value_type with corpus_type
  using corpus_type = std::tuple<int>;
  static constexpr bool has_custom_corpus_type = true;

  template <typename PRNG>
  corpus_type Init(PRNG& prng) {
    // Minimal code to exercise prng.
    corpus_type result = {absl::Uniform<value_type>(prng, i, i + 1)};
    ++i;
    return result;
  }

  template <typename PRNG>
  void Mutate(corpus_type& val, PRNG& prng, bool only_shrink) {
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

// TODO(b/246448769): Rewrite the test to decrease the chance of failure.
TEST(ProtocolBuffer,
     RepeatedMutationEventuallyMutatesAllFieldsOfArbitraryProtobuf) {
  Domain<internal::TestProtobuf> domain = Arbitrary<internal::TestProtobuf>();

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

// TODO(b/246652379): Re-enable after b/231212420 is fixed.
TEST(ProtocolBuffer,
     DISABLED_ShrinkingEventuallyUnsetsAndEmptiesAllFieldsOfArbitraryProtobuf) {
  Domain<internal::TestProtobuf> domain = Arbitrary<internal::TestProtobuf>();

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

// TODO(JunyangShao): Consider split this test into:
// - OptionalFieldIsEventuallySet
// - OptionalFieldIsEventuallyUnset
// - OptionalFieldInSubprotoIsEventuallySet
// - OptionalFieldInSubprotoIsEventuallyUnset
// - MinimizationEventuallyProducesMinimalProto
TEST(ProtocolBuffer, ArbitraryWithRequiredHasAllMutations) {
  auto domain = Arbitrary<internal::TestProtobufWithRequired>();

  absl::BitGen bitgen;
  Value val(domain, bitgen);

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();

  // Verify that some changes happen
  enum ThingsToFind {
    kOptionalEmpty,
    kOptionalFull,
    kRequiredSubWithOptionalEmpty,
    kRequiredSubWithOptionalFull,
    kOptionalSubWithRequired
  };
  absl::flat_hash_set<ThingsToFind> to_find;
  int i = 0;
  while (to_find.size() < 5 && ++i < 1000) {
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();

    using ValueType = decltype(val.user_value);
    const ValueType* v = &val.user_value;
    int depth = 1000;
    while (--depth > 0) {
      to_find.insert(v->has_i32() ? kOptionalFull : kOptionalEmpty);
      if (v->has_req_sub()) {
        to_find.insert(v->req_sub().has_subproto_i32()
                           ? kRequiredSubWithOptionalFull
                           : kRequiredSubWithOptionalEmpty);
      }
      if (v->has_sub_req()) {
        to_find.insert(kOptionalSubWithRequired);
        v = &v->sub_req();
      } else {
        break;
      }
    }
    val.Mutate(domain, bitgen, false);
  }
  EXPECT_THAT(to_find, UnorderedElementsAre(kOptionalEmpty, kOptionalFull,
                                            kRequiredSubWithOptionalEmpty,
                                            kRequiredSubWithOptionalFull,
                                            kOptionalSubWithRequired));

  // Test shrinking.
  // Required fields should never be removed.
  const auto is_minimal = [&] {
    auto& v = val.user_value;
    return !v.has_i32() && v.req_i32() == 0 && v.req_e() == 0 &&
           !v.req_sub().has_subproto_i32() && !v.has_sub_req();
  };
  while (!is_minimal()) {
    const auto prev = val;
    val.Mutate(domain, bitgen, true);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();
  }

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value.DebugString();
}

TEST(ProtocolBuffer, CanUsePerFieldDomains) {
  using internal::TestProtobuf;
  Domain<TestProtobuf> domain =
      Arbitrary<internal::TestProtobuf>()
          .WithInt32Field("i32", InRange(1, 4))
          .WithStringField("str", PrintableAsciiString().WithSize(4))
          .WithEnumField(
              "e", ElementOf<int>({TestProtobuf::Label2, TestProtobuf::Label4}))
          .WithRepeatedBoolField("rep_b", VectorOf(Just(true)).WithSize(2))
          .WithProtobufField(
              "subproto", Arbitrary<internal::TestSubProtobuf>().WithInt32Field(
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
      Arbitrary<internal::TestProtobuf>().WithStringField(
          "i32", Arbitrary<std::string>()),
      "Failed precondition.*"
      "does not match field `fuzztest.internal.TestProtobuf.i32`");
}

TEST(ProtocolBuffer, SerializeAndParseCanHandleExtensions) {
  auto domain = Arbitrary<internal::TestProtobufWithExtension>();
  internal::TestProtobufWithExtension user_value;
  user_value.SetExtension(internal::ProtoExtender::ext, "Hello?!?!");
  auto corpus_value = domain.FromValue(user_value);
  EXPECT_TRUE(corpus_value != std::nullopt);
  auto serialized = domain.SerializeCorpus(corpus_value.value());
  auto parsed = domain.ParseCorpus(serialized);
  EXPECT_TRUE(parsed != std::nullopt);
  auto user_value_after_serialize_parse = domain.GetValue(parsed.value());
  EXPECT_EQ("Hello?!?!", user_value_after_serialize_parse.GetExtension(
                             internal::ProtoExtender::ext));
}

TEST(ProtocolBufferEnum, Arbitrary) {
  auto domain = Arbitrary<internal::TestProtobuf_Enum>();
  absl::BitGen bitgen;
  Value val(domain, bitgen);

  Set<internal::TestProtobuf_Enum> s;
  while (s.size() < internal::TestProtobuf_Enum_descriptor()->value_count()) {
    s.insert(val.user_value);
    val.Mutate(domain, bitgen, false);
  }
  val.Mutate(domain, bitgen, true);
}

TEST(ProtocolBuffer, CountNumberOfFieldsCorrect) {
  using T = internal::TestProtobuf;
  using SubT = internal::TestSubProtobuf;
  auto domain = Arbitrary<T>();
  T v;
  auto corpus_v_uninitialized = domain.FromValue(v);
  EXPECT_TRUE(corpus_v_uninitialized != std::nullopt);
  EXPECT_EQ(domain.CountNumberOfFields(corpus_v_uninitialized.value()), 25);
  v.set_allocated_subproto(new SubT());
  auto corpus_v_initizalize_one_optional_proto = domain.FromValue(v);
  EXPECT_TRUE(corpus_v_initizalize_one_optional_proto != std::nullopt);
  EXPECT_EQ(domain.CountNumberOfFields(
                corpus_v_initizalize_one_optional_proto.value()),
            27);
  v.add_rep_subproto();
  auto corpus_v_initizalize_one_repeated_proto_1 = domain.FromValue(v);
  EXPECT_TRUE(corpus_v_initizalize_one_repeated_proto_1 != std::nullopt);
  EXPECT_EQ(domain.CountNumberOfFields(
                corpus_v_initizalize_one_repeated_proto_1.value()),
            29);
  v.add_rep_subproto();
  auto corpus_v_initizalize_one_repeated_proto_2 = domain.FromValue(v);
  EXPECT_TRUE(corpus_v_initizalize_one_repeated_proto_2 != std::nullopt);
  EXPECT_EQ(domain.CountNumberOfFields(
                corpus_v_initizalize_one_repeated_proto_2.value()),
            31);
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

}  // namespace
}  // namespace fuzztest
