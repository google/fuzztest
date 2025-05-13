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
#include <type_traits>
#include <utility>
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

using ::fuzztest::internal::DefaultTestFbsTable;
using ::fuzztest::internal::OptionalTestFbsTable;
using ::fuzztest::internal::RequiredTestFbsTable;
using ::testing::_;
using ::testing::Contains;
using ::testing::Each;
using ::testing::IsTrue;
using ::testing::Pair;
using ::testing::ResultOf;

template <typename T>
inline bool Eq(T rhs, T lhs) {
  static_assert(!std::is_pointer_v<T>, "T cannot be a pointer type");
  return lhs == rhs;
}

template <>
inline bool Eq<const flatbuffers::String*>(const flatbuffers::String* rhs,
                                           const flatbuffers::String* lhs) {
  return (rhs == nullptr && lhs == nullptr) ||
         (rhs != nullptr && lhs != nullptr && rhs->str() == lhs->str());
};

const internal::DefaultTestFbsTable* CreateDefaultTestFbsTable(
    flatbuffers::FlatBufferBuilder& fbb) {
  auto table_offset = internal::CreateDefaultTestFbsTableDirect(
      fbb,
      true,                         // b
      1,                            // i8
      2,                            // i16
      3,                            // i32
      4,                            // i64
      5,                            // u8
      6,                            // u16
      7,                            // u32
      8,                            // u64
      9.0,                          // f
      10.0,                         // d
      "foo bar baz",                // str
      internal::TestFbsEnum_Second  // e
  );
  fbb.Finish(table_offset);
  return flatbuffers::GetRoot<DefaultTestFbsTable>(fbb.GetBufferPointer());
}

TEST(FlatbuffersMetaTest, IsFlatbuffersTable) {
  static_assert(internal::is_flatbuffers_table_v<DefaultTestFbsTable>);
  static_assert(!internal::is_flatbuffers_table_v<int>);
  static_assert(!internal::is_flatbuffers_table_v<std::optional<bool>>);
}

TEST(FlatbuffersTableDomainImplTest, DefaultTestFbsTableValueRoundTrip) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table = CreateDefaultTestFbsTable(fbb);

  auto domain = Arbitrary<DefaultTestFbsTable>();
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
  EXPECT_EQ(new_table->e(), internal::TestFbsEnum_Second);
}

TEST(FlatbuffersTableDomainImplTest, InitGeneratesSeeds) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table = CreateDefaultTestFbsTable(fbb);

  auto domain = Arbitrary<DefaultTestFbsTable>();
  domain.WithSeeds({table});

  std::vector<Value<decltype(domain)>> values;
  absl::BitGen bitgen;
  values.reserve(1000);
  for (int i = 0; i < 1000; ++i) {
    Value value(domain, bitgen);
    values.push_back(std::move(value));
  }

  EXPECT_THAT(values, Contains(ResultOf(
                          [table](const auto& val) {
                            return (Eq(val.user_value->b(), table->b()) &&
                                    Eq(val.user_value->i8(), table->i8()) &&
                                    Eq(val.user_value->i16(), table->i16()) &&
                                    Eq(val.user_value->i32(), table->i32()) &&
                                    Eq(val.user_value->i64(), table->i64()) &&
                                    Eq(val.user_value->u8(), table->u8()) &&
                                    Eq(val.user_value->u16(), table->u16()) &&
                                    Eq(val.user_value->u32(), table->u32()) &&
                                    Eq(val.user_value->u64(), table->u64()) &&
                                    Eq(val.user_value->f(), table->f()) &&
                                    Eq(val.user_value->d(), table->d()) &&
                                    Eq(val.user_value->f(), table->f()) &&
                                    Eq(val.user_value->e(), table->e()) &&
                                    Eq(val.user_value->str(), table->str()));
                          },
                          IsTrue())));
}

TEST(FlatbuffersTableDomainImplTest, EventuallyMutatesAllTableFields) {
  absl::flat_hash_map<std::string, bool> mutated_fields{
      {"b", false},   {"i8", false}, {"i16", false}, {"i32", false},
      {"i64", false}, {"u8", false}, {"u16", false}, {"u32", false},
      {"u64", false}, {"f", false},  {"d", false},   {"str", false},
      {"e", false},
  };

  auto domain = Arbitrary<DefaultTestFbsTable>();

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
    mutated_fields["str"] |= Eq(mut->str(), init->str());
    mutated_fields["e"] |= !Eq(mut->e(), init->e());

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

TEST(FlatbuffersTableDomainImplTest,
     OptionalTestFbsTableEventuallyBecomeEmpty) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table_offset = internal::CreateOptionalTestFbsTableDirect(
      fbb,
      true,                         // b
      1,                            // i8
      2,                            // i16
      3,                            // i32
      4,                            // i64
      5,                            // u8
      6,                            // u16
      7,                            // u32
      8,                            // u64
      9.0,                          // f
      10.0,                         // d
      "foo bar baz",                // str
      internal::TestFbsEnum_Second  // e
  );
  fbb.Finish(table_offset);
  auto table =
      flatbuffers::GetRoot<OptionalTestFbsTable>(fbb.GetBufferPointer());

  auto domain = Arbitrary<OptionalTestFbsTable>();
  Value val(domain, table);
  absl::BitGen bitgen;

  absl::flat_hash_map<std::string, bool> null_fields{
      {"b", false},   {"i8", false}, {"i16", false}, {"i32", false},
      {"i64", false}, {"u8", false}, {"u16", false}, {"u32", false},
      {"u64", false}, {"f", false},  {"d", false},   {"str", false},
      {"e", false},
  };

  for (size_t i = 0; i < 10'000; ++i) {
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
    null_fields["e"] |= !v->e().has_value();

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

TEST(FlatbuffersTableDomainImplTest, RequiredTestFbsTableFieldsAlwaysSet) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table_offset =
      internal::CreateRequiredTestFbsTableDirect(fbb,
                                                 "foo bar baz"  // str
      );
  fbb.Finish(table_offset);
  auto table =
      flatbuffers::GetRoot<RequiredTestFbsTable>(fbb.GetBufferPointer());

  auto domain = Arbitrary<RequiredTestFbsTable>();
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

}  // namespace
}  // namespace fuzztest
