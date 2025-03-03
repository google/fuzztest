// Copyright 2025 Google LLC
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

#include <cassert>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/random/random.h"
#include "flatbuffers/base.h"
#include "flatbuffers/buffer.h"
#include "flatbuffers/flatbuffer_builder.h"
#include "flatbuffers/string.h"
#include "flatbuffers/vector.h"
#include "./fuzztest/domain.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/flatbuffers.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/test_flatbuffers_generated.h"

namespace fuzztest {
namespace {

using ::fuzztest::internal::DefaultTable;
using ::fuzztest::internal::OptionalTable;
using ::fuzztest::internal::RequiredTable;
using ::testing::_;
using ::testing::Each;
using ::testing::HasSubstr;
using ::testing::Pair;

template <typename T>
inline bool Eq(T lhs, T rhs) {
  static_assert(!std::is_pointer_v<T>, "T cannot be a pointer type");
  return rhs == lhs;
}

template <>
inline bool Eq<const flatbuffers::String*>(const flatbuffers::String* lhs,
                                           const flatbuffers::String* rhs) {
  if (lhs == nullptr && rhs == nullptr) return true;
  if (lhs == nullptr || rhs == nullptr) return false;
  return lhs->str() == rhs->str();
}

template <>
inline bool Eq<const DefaultTable*>(const DefaultTable* lhs,
                                    const DefaultTable* rhs) {
  if (lhs == nullptr && rhs == nullptr) return true;
  if (lhs == nullptr || rhs == nullptr) return false;
  bool eq_b = Eq(lhs->b(), rhs->b());
  bool eq_i8 = Eq(lhs->i8(), rhs->i8());
  bool eq_i16 = Eq(lhs->i16(), rhs->i16());
  bool eq_i32 = Eq(lhs->i32(), rhs->i32());
  bool eq_i64 = Eq(lhs->i64(), rhs->i64());
  bool eq_u8 = Eq(lhs->u8(), rhs->u8());
  bool eq_u16 = Eq(lhs->u16(), rhs->u16());
  bool eq_u32 = Eq(lhs->u32(), rhs->u32());
  bool eq_u64 = Eq(lhs->u64(), rhs->u64());
  bool eq_f = Eq(lhs->f(), rhs->f());
  bool eq_d = Eq(lhs->d(), rhs->d());
  bool eq_str = Eq(lhs->str(), rhs->str());
  bool eq_ei8 = Eq(lhs->ei8(), rhs->ei8());
  bool eq_ei16 = Eq(lhs->ei16(), rhs->ei16());
  bool eq_ei32 = Eq(lhs->ei32(), rhs->ei32());
  bool eq_ei64 = Eq(lhs->ei64(), rhs->ei64());
  bool eq_eu8 = Eq(lhs->eu8(), rhs->eu8());
  bool eq_eu16 = Eq(lhs->eu16(), rhs->eu16());
  bool eq_eu32 = Eq(lhs->eu32(), rhs->eu32());
  bool eq_eu64 = Eq(lhs->eu64(), rhs->eu64());
  return eq_b && eq_i8 && eq_i16 && eq_i32 && eq_i64 && eq_u8 && eq_u16 &&
         eq_u32 && eq_u64 && eq_f && eq_d && eq_str && eq_ei8 && eq_ei16 &&
         eq_ei32 && eq_ei64 && eq_eu8 && eq_eu16 && eq_eu32 && eq_eu64;
}

const internal::DefaultTable* CreateDefaultTable(
    flatbuffers::FlatBufferBuilder& fbb) {
  auto table_offset =
      internal::CreateDefaultTableDirect(fbb,
                                         true,                        // b
                                         1,                           // i8
                                         2,                           // i16
                                         3,                           // i32
                                         4,                           // i64
                                         5,                           // u8
                                         6,                           // u16
                                         7,                           // u32
                                         8,                           // u64
                                         9.0,                         // f
                                         10.0,                        // d
                                         "foo bar baz",               // str
                                         internal::ByteEnum_First,    // ei8
                                         internal::ShortEnum_First,   // ei16
                                         internal::IntEnum_First,     // ei32
                                         internal::LongEnum_First,    // ei64
                                         internal::UByteEnum_First,   // eu8
                                         internal::UShortEnum_First,  // eu16
                                         internal::UIntEnum_First,    // eu32
                                         internal::ULongEnum_First    // eu64
      );
  fbb.Finish(table_offset);
  return flatbuffers::GetRoot<DefaultTable>(fbb.GetBufferPointer());
}

TEST(FlatbuffersMetaTest, IsFlatbuffersTable) {
  static_assert(internal::is_flatbuffers_table_v<DefaultTable>);
  static_assert(!internal::is_flatbuffers_table_v<int>);
  static_assert(!internal::is_flatbuffers_table_v<std::optional<bool>>);
}

TEST(FlatbuffersTableDomainImplTest, DefaultTableValueRoundTrip) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table = CreateDefaultTable(fbb);

  auto domain = Arbitrary<DefaultTable>();
  auto corpus = domain.FromValue(table);
  ASSERT_TRUE(corpus.has_value());
  ASSERT_OK(domain.ValidateCorpusValue(*corpus));

  auto ir = domain.SerializeCorpus(corpus.value());

  auto new_corpus = domain.ParseCorpus(ir);
  ASSERT_TRUE(new_corpus.has_value());
  ASSERT_OK(domain.ValidateCorpusValue(*new_corpus));

  auto new_table = domain.GetValue(*new_corpus);
  EXPECT_EQ(new_table->b(), true);
  EXPECT_EQ(new_table->i8(), 1);
  EXPECT_EQ(new_table->i16(), 2);
  EXPECT_EQ(new_table->i32(), 3);
  EXPECT_EQ(new_table->i64(), 4);
  EXPECT_EQ(new_table->u8(), 5);
  EXPECT_EQ(new_table->u16(), 6);
  EXPECT_EQ(new_table->u32(), 7);
  EXPECT_EQ(new_table->u64(), 8);
  EXPECT_EQ(new_table->f(), 9.0);
  EXPECT_EQ(new_table->d(), 10.0);
  EXPECT_EQ(new_table->str()->str(), "foo bar baz");
  EXPECT_EQ(new_table->ei8(), internal::ByteEnum_First);
  EXPECT_EQ(new_table->ei16(), internal::ShortEnum_First);
  EXPECT_EQ(new_table->ei32(), internal::IntEnum_First);
  EXPECT_EQ(new_table->ei64(), internal::LongEnum_First);
  EXPECT_EQ(new_table->eu8(), internal::UByteEnum_First);
  EXPECT_EQ(new_table->eu16(), internal::UShortEnum_First);
  EXPECT_EQ(new_table->eu32(), internal::UIntEnum_First);
  EXPECT_EQ(new_table->eu64(), internal::ULongEnum_First);
}

TEST(FlatbuffersTableDomainImplTest, InitGeneratesSeeds) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table = CreateDefaultTable(fbb);

  auto domain = Arbitrary<DefaultTable>();
  domain.WithSeeds({table});

  std::vector<Value<decltype(domain)>> values;
  absl::BitGen bitgen;
  bool is_seed = false;
  for (int i = 0; i < 1000; ++i) {
    Value value(domain, bitgen);
    is_seed |= Eq(value.user_value, table);
    if (is_seed) {
      break;
    }
  }
  EXPECT_TRUE(is_seed);
}

TEST(FlatbuffersTableDomainImplTest, EventuallyMutatesAllTableFields) {
  absl::flat_hash_map<std::string, bool> mutated_fields{
      {"b", false},   {"i8", false},   {"i16", false},  {"i32", false},
      {"i64", false}, {"u8", false},   {"u16", false},  {"u32", false},
      {"u64", false}, {"f", false},    {"d", false},    {"str", false},
      {"ei8", false}, {"ei16", false}, {"ei32", false}, {"ei64", false},
      {"eu8", false}, {"eu16", false}, {"eu32", false}, {"eu64", false},
  };

  auto domain = Arbitrary<DefaultTable>();

  absl::BitGen bitgen;
  Value initial_val(domain, bitgen);
  Value val(initial_val);

  for (size_t i = 0; i < 10'000; ++i) {
    val.Mutate(domain, bitgen, {}, false);
    const auto& mut = val.user_value;
    const auto& init = initial_val.user_value;

    mutated_fields["b"] |= !Eq(mut->b(), init->b());
    mutated_fields["i8"] |= !Eq(mut->i8(), init->i8());
    mutated_fields["i16"] |= !Eq(mut->i16(), init->i16());
    mutated_fields["i32"] |= !Eq(mut->i32(), init->i32());
    mutated_fields["i64"] |= !Eq(mut->i64(), init->i64());
    mutated_fields["u8"] |= !Eq(mut->u8(), init->u8());
    mutated_fields["u16"] |= !Eq(mut->u16(), init->u16());
    mutated_fields["u32"] |= !Eq(mut->u32(), init->u32());
    mutated_fields["u64"] |= !Eq(mut->u64(), init->u64());
    mutated_fields["f"] |= !Eq(mut->f(), init->f());
    mutated_fields["d"] |= !Eq(mut->d(), init->d());
    mutated_fields["str"] |= !Eq(mut->str(), init->str());
    mutated_fields["ei8"] |= !Eq(mut->ei8(), init->ei8());
    mutated_fields["ei16"] |= !Eq(mut->ei16(), init->ei16());
    mutated_fields["ei32"] |= !Eq(mut->ei32(), init->ei32());
    mutated_fields["ei64"] |= !Eq(mut->ei64(), init->ei64());
    mutated_fields["eu8"] |= !Eq(mut->eu8(), init->eu8());
    mutated_fields["eu16"] |= !Eq(mut->eu16(), init->eu16());
    mutated_fields["eu32"] |= !Eq(mut->eu32(), init->eu32());
    mutated_fields["eu64"] |= !Eq(mut->eu64(), init->eu64());

    bool all_mutated = true;
    for (const auto& [name, mutated] : mutated_fields) {
      all_mutated &= mutated;
      if (!mutated) {
        break;
      }
    }
    if (all_mutated) {
      break;
    }
  }

  EXPECT_THAT(mutated_fields, Each(Pair(_, true)));
}

TEST(FlatbuffersTableDomainImplTest, OptionalTableEventuallyBecomeEmpty) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table_offset =
      internal::CreateOptionalTableDirect(fbb,
                                          true,                        // b
                                          1,                           // i8
                                          2,                           // i16
                                          3,                           // i32
                                          4,                           // i64
                                          5,                           // u8
                                          6,                           // u16
                                          7,                           // u32
                                          8,                           // u64
                                          9.0,                         // f
                                          10.0,                        // d
                                          "foo bar baz",               // str
                                          internal::ByteEnum_First,    // ei8
                                          internal::ShortEnum_First,   // ei16
                                          internal::IntEnum_First,     // ei32
                                          internal::LongEnum_First,    // ei64
                                          internal::UByteEnum_First,   // eu8
                                          internal::UShortEnum_First,  // eu16
                                          internal::UIntEnum_First,    // eu32
                                          internal::ULongEnum_First    // eu64
      );
  fbb.Finish(table_offset);
  auto table = flatbuffers::GetRoot<OptionalTable>(fbb.GetBufferPointer());

  auto domain = Arbitrary<OptionalTable>();
  Value val(domain, table);
  absl::BitGen bitgen;

  absl::flat_hash_map<std::string, bool> null_fields{
      {"b", false},   {"i8", false},   {"i16", false},  {"i32", false},
      {"i64", false}, {"u8", false},   {"u16", false},  {"u32", false},
      {"u64", false}, {"f", false},    {"d", false},    {"str", false},
      {"ei8", false}, {"ei16", false}, {"ei32", false}, {"ei64", false},
      {"eu8", false}, {"eu16", false}, {"eu32", false}, {"eu64", false},
  };

  for (size_t i = 0; i < 100'000; ++i) {
    val.Mutate(domain, bitgen, {}, true);
    const auto& v = val.user_value;

    null_fields["b"] |= !v->b().has_value();
    null_fields["i8"] |= !v->i8().has_value();
    null_fields["i16"] |= !v->i16().has_value();
    null_fields["i32"] |= !v->i32().has_value();
    null_fields["i64"] |= !v->i64().has_value();
    null_fields["u8"] |= !v->u8().has_value();
    null_fields["u16"] |= !v->u16().has_value();
    null_fields["u32"] |= !v->u32().has_value();
    null_fields["u64"] |= !v->u64().has_value();
    null_fields["f"] |= !v->f().has_value();
    null_fields["d"] |= !v->d().has_value();
    null_fields["str"] |= v->str() == nullptr;
    null_fields["ei8"] |= !v->ei8().has_value();
    null_fields["ei16"] |= !v->ei16().has_value();
    null_fields["ei32"] |= !v->ei32().has_value();
    null_fields["ei64"] |= !v->ei64().has_value();
    null_fields["eu8"] |= !v->eu8().has_value();
    null_fields["eu16"] |= !v->eu16().has_value();
    null_fields["eu32"] |= !v->eu32().has_value();
    null_fields["eu64"] |= !v->eu64().has_value();

    bool all_null = true;
    for (const auto& [name, is_null] : null_fields) {
      all_null &= is_null;
      if (!is_null) {
        break;
      }
    }
    if (all_null) {
      break;
    }
  }

  EXPECT_THAT(null_fields, Each(Pair(_, true)));
}

TEST(FlatbuffersTableDomainImplTest, RequiredTableFieldsAlwaysSet) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table_offset = internal::CreateRequiredTableDirect(fbb,
                                                          "foo bar baz"  // str
  );
  fbb.Finish(table_offset);
  auto table = flatbuffers::GetRoot<RequiredTable>(fbb.GetBufferPointer());

  auto domain = Arbitrary<RequiredTable>();
  Value val(domain, table);
  absl::BitGen bitgen;

  absl::flat_hash_map<std::string, bool> set_fields{{"str", false}};

  for (size_t i = 0; i < 10'000; ++i) {
    val.Mutate(domain, bitgen, {}, true);
    const auto& v = val.user_value;

    set_fields["str"] |= v->str() != nullptr;

    bool all_set = true;
    for (const auto& [name, is_set] : set_fields) {
      all_set &= is_set;
      if (!is_set) {
        break;
      }
    }
    if (all_set) {
      break;
    }
  }

  EXPECT_THAT(set_fields, Each(Pair(_, true)));
}

TEST(FlatbuffersTableDomainImplTest, Printer) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table = CreateDefaultTable(fbb);
  auto domain = Arbitrary<DefaultTable>();
  auto corpus = domain.FromValue(table);
  ASSERT_TRUE(corpus.has_value());

  auto printer = domain.GetPrinter();
  std::string out;
  printer.PrintCorpusValue(*corpus, &out,
                           domain_implementor::PrintMode::kHumanReadable);

  EXPECT_THAT(out, HasSubstr("b: (true)"));
  EXPECT_THAT(out, HasSubstr("i8: (1)"));
  EXPECT_THAT(out, HasSubstr("i16: (2)"));
  EXPECT_THAT(out, HasSubstr("i32: (3)"));
  EXPECT_THAT(out, HasSubstr("i64: (4)"));
  EXPECT_THAT(out, HasSubstr("u8: (5)"));
  EXPECT_THAT(out, HasSubstr("u16: (6)"));
  EXPECT_THAT(out, HasSubstr("u32: (7)"));
  EXPECT_THAT(out, HasSubstr("u64: (8)"));
  EXPECT_THAT(out, HasSubstr("f: (9.f)"));
  EXPECT_THAT(out, HasSubstr("d: (10.)"));
  EXPECT_THAT(out, HasSubstr("str: (\"foo bar baz\")"));
  EXPECT_THAT(out, HasSubstr("ei8: (0)"));
  EXPECT_THAT(out, HasSubstr("ei16: (0)"));
  EXPECT_THAT(out, HasSubstr("ei32: (0)"));
  EXPECT_THAT(out, HasSubstr("ei64: (0)"));
  EXPECT_THAT(out, HasSubstr("eu8: (0)"));
  EXPECT_THAT(out, HasSubstr("eu16: (0)"));
  EXPECT_THAT(out, HasSubstr("eu32: (0)"));
  EXPECT_THAT(out, HasSubstr("eu64: (0)"));
}

}  // namespace
}  // namespace fuzztest
