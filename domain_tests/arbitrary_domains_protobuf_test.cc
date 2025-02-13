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

#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/domain.h"  // IWYU pragma: keep
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/test_protobuf.pb.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"
#include "google/protobuf/message_lite.h"
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
using ::testing::IsTrue;
using ::testing::ResultOf;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAre;

TEST(ArbitraryProtocolBufferTest, InitGeneratesSeeds) {
  TestProtobuf seed;
  seed.set_i32(42);
  seed.set_str("Hello");

  EXPECT_THAT(
      GenerateInitialValues(Arbitrary<TestProtobuf>().WithSeeds({seed}), 1000),
      Contains(ResultOf(
          [&seed](const auto& val) {
            return google::protobuf::util::MessageDifferencer::Equals(val.user_value,
                                                            seed);
          },
          IsTrue())));
}

// TODO(b/246448769): Rewrite the test to decrease the chance of failure.
TEST(ProtocolBuffer,
     RepeatedMutationEventuallyMutatesAllFieldsOfArbitraryProtobuf) {
  Domain<TestProtobuf> domain = Arbitrary<TestProtobuf>();

  absl::BitGen bitgen;
  Value val(domain, bitgen);

  const auto verify_field_changes = [&](absl::string_view name, auto has,
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
      val.Mutate(domain, bitgen, {}, false);
    }
    EXPECT_GT(iterations, 0)
        << "Field: " << name << " -- " << testing::PrintToString(values);
  };

  const auto verify_repeated_field_changes = [&](absl::string_view name,
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
      val.Mutate(domain, bitgen, {}, false);
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
    val.Mutate(domain, bitgen, {}, false);
  }

  // We verify that the object actually has things in it. This can technically
  // fail if the very last operation done above was to unset the very last set
  // field, but it is very unlikely.
  ASSERT_NE(val.user_value.ByteSizeLong(), 0);

  // ByteSizeLong() == 0 is a simple way to determine that all fields are unset.
  for (int iteration = 0;
       val.user_value.ByteSizeLong() > 0 && iteration < 50'000; ++iteration) {
    const auto prev = val;
    val.Mutate(domain, bitgen, {}, true);
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

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;

  for (int i = 0; i < 1000; ++i) {
    val.Mutate(domain, bitgen, {}, false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;
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

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;

  // With the restricted domain, the probability of unsetting the field i32 is
  // at least 1/800. Hence, within 11000 iterations we'll fail to observe this
  // event with probability at most 10^(-6).
  for (int i = 0; i < 11000; ++i) {
    val.Mutate(domain, bitgen, {}, false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;
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

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;

  for (int i = 0; i < 1000; ++i) {
    val.Mutate(domain, bitgen, {}, false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;
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

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;

  // With the restricted domain, the probability of unsetting the field
  // req_sub.subproto_i32 is at least 1/800. Hence, within 11000 iterations
  // we'll fail to observe this event with probability at most 10^(-6).
  for (int i = 0; i < 11000; ++i) {
    val.Mutate(domain, bitgen, {}, false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;
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

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;

  for (int i = 0; i < 1000; ++i) {
    val.Mutate(domain, bitgen, {}, false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;
    if (val.user_value.has_sub_req()) {
      ASSERT_TRUE(val.user_value.sub_req().IsInitialized()) << val.user_value;
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

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;

  bool found = false;
  for (int i = 0; i < 1000 && !found; ++i) {
    val.Mutate(domain, bitgen, {}, false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;
    for (const auto& pair : val.user_value.map_sub_req()) {
      found = true;
      ASSERT_TRUE(pair.second.IsInitialized()) << pair.second;
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

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;

  for (int i = 0; i < 1000; ++i) {
    val.Mutate(domain, bitgen, {}, false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;
  }

  const auto is_minimal = [](const auto& v) {
    return !v.has_i32() && v.req_i32() == 0 && v.req_e() == 0 &&
           !v.req_sub().has_subproto_i32() &&
           v.req_sub().subproto_rep_i32().empty() && !v.has_sub_req();
  };

  while (!is_minimal(val.user_value)) {
    val.Mutate(domain, bitgen, {}, true);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;
  }
}

TEST(ProtocolBufferWithRecursiveFields, InfiniteleyRecursiveFieldsAreNotSet) {
  auto domain = Arbitrary<internal::TestProtobufWithRepeatedRecursionSubproto>()
                    .WithRepeatedFieldsAlwaysSet();
  absl::BitGen bitgen;
  Value val(domain, bitgen);

  ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;

  for (int i = 0; i < 1000; ++i) {
    val.Mutate(domain, bitgen, {}, false);
    ASSERT_TRUE(val.user_value.IsInitialized()) << val.user_value;
    ASSERT_FALSE(val.user_value.has_list()) << val.user_value;
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
    val.Mutate(domain, bitgen, {}, false);
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

bool IsInt64(const FieldDescriptor* field) {
  return field->type() == FieldDescriptor::TYPE_INT64;
}

TEST(ProtocolBuffer, ValidationRejectsIncorrectlySetOneofField) {
  Domain<TestProtobuf> domain_a = Arbitrary<TestProtobuf>();
  Domain<TestProtobuf> domain_b = Arbitrary<TestProtobuf>()
                                      .WithOneofAlwaysSet("oneof_field")
                                      .WithFieldsUnset(IsInt64)
                                      .WithFieldUnset("oneof_u32");
  TestProtobuf user_value_1;
  user_value_1.set_oneof_u32(1);
  auto corpus_value_1 = domain_a.FromValue(user_value_1);

  EXPECT_THAT(
      domain_b.ValidateCorpusValue(*corpus_value_1),
      IsInvalid(
          "Invalid value for field oneof_u32 >> Optional value must be null"));

  TestProtobuf user_value_2;
  user_value_2.set_oneof_i64(1);
  auto corpus_value_2 = domain_a.FromValue(user_value_2);

  EXPECT_THAT(
      domain_b.ValidateCorpusValue(*corpus_value_2),
      IsInvalid(
          "Invalid value for field oneof_i64 >> Optional value must be null"));
}

TEST(ProtocolBuffer, ValidationRejectsUnsetOneofsWithOneofAlwaysSet) {
  absl::BitGen bitgen;

  Domain<TestProtobuf> domain_a = Arbitrary<TestProtobuf>();
  Domain<TestProtobuf> domain_b =
      Arbitrary<TestProtobuf>().WithOneofAlwaysSet("oneof_field");

  TestProtobuf user_value;
  auto corpus_value = domain_a.FromValue(user_value);

  EXPECT_THAT(domain_b.ValidateCorpusValue(*corpus_value),
              IsInvalid("Oneof oneof_field is not set"));
}

TEST(ProtocolBufferEnum, Arbitrary) {
  auto domain = Arbitrary<TestProtobuf_Enum>();
  absl::BitGen bitgen;
  Value val(domain, bitgen);

  Set<TestProtobuf_Enum> s;
  while (s.size() < internal::TestProtobuf_Enum_descriptor()->value_count()) {
    s.insert(val.user_value);
    val.Mutate(domain, bitgen, {}, false);
  }
  val.Mutate(domain, bitgen, {}, true);
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

auto FieldNameHasSubstr(absl::string_view field_name) {
  return [field_name = std::string(field_name)](const FieldDescriptor* field) {
    return absl::StrContains(field->name(), field_name);
  };
}

TEST(ProtocolBuffer, ProtobufOfIsCustomizable) {
  auto domain =
      ProtobufOf([] { return &TestProtobuf::default_instance(); })
          .WithFieldsAlwaysSet(FieldNameHasSubstr("i32"))
          .WithFieldsUnset(FieldNameHasSubstr("i64"))
          .WithOptionalFieldsUnset(FieldNameHasSubstr("u32"))
          .WithOptionalFieldsAlwaysSet(FieldNameHasSubstr("u64"))
          .WithRepeatedFieldsUnset(FieldNameHasSubstr("32"))
          .WithRepeatedFieldsAlwaysSet(FieldNameHasSubstr("64"))
          .WithRepeatedFieldsMinSize(FieldNameHasSubstr("rep_b"), 3)
          .WithRepeatedFieldsMaxSize(FieldNameHasSubstr("rep_b"), 4)
          .WithFloatFields(InRange(1.0f, 2.0f))
          .WithOptionalDoubleFields(InRange(-1.0, 1.0))
          .WithRepeatedDoubleFields(InRange(-1.0, 1.0))
          .WithProtobufFields(FieldNameHasSubstr("subproto"),
                              Arbitrary<TestSubProtobuf>().WithFieldsUnset())
          .WithRepeatedProtobufFields(
              FieldNameHasSubstr("subproto"),
              Arbitrary<TestSubProtobuf>().WithFieldsAlwaysSet());
  EXPECT_THAT(
      GenerateInitialValues(domain, 1000),
      Each(ResultOf(
          [](const Value<decltype(domain)>& val) {
            auto v =
              *dynamic_cast<TestProtobuf*>(val.user_value.get());
            for (const auto& s : v.rep_subproto()) {
              if (!s.has_subproto_i32()) return false;
              if (s.subproto_rep_i32_size() == 0) return false;
            }
            if (v.has_subproto()) {
              auto& s = v.subproto();
              if (s.has_subproto_i32()) return false;
              if (s.subproto_rep_i32_size() > 0) return false;
            }
            for (const auto& d : v.rep_d()) {
              if (d < -1 || d > 1) return false;
            }
            if (v.has_d()) {
              if (v.d() < -1 || v.d() > 1) return false;
            }
            if (v.has_f()) {
              if (v.f() < 1 || v.f() > 2) return false;
            }
            if (v.rep_b_size() < 3) return false;
            if (v.rep_b_size() > 4) return false;
            if (v.rep_i32_size() > 0) return false;
            if (v.rep_u32_size() > 0) return false;
            if (v.rep_i64_size() == 0) return false;
            if (v.rep_u64_size() == 0) return false;
            if (v.has_u32()) return false;
            if (!v.has_u64()) return false;
            if (!v.has_i32()) return false;
            if (v.has_i64()) return false;
            return true;
          },
          true)));
}

}  // namespace
}  // namespace fuzztest
