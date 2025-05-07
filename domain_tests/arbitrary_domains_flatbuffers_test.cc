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

#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/random/random.h"
#include "flatbuffers/base.h"
#include "flatbuffers/buffer.h"
#include "flatbuffers/flatbuffer_builder.h"
#include "flatbuffers/string.h"
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
using ::testing::Contains;
using ::testing::IsTrue;
using ::testing::ResultOf;

TEST(FlatbuffersMetaTest, IsFlatbuffersTable) {
  static_assert(internal::is_flatbuffers_table_v<DefaultTestFbsTable>);
  static_assert(!internal::is_flatbuffers_table_v<int>);
  static_assert(!internal::is_flatbuffers_table_v<std::optional<bool>>);
}

TEST(FlatbuffersTableImplTest, DefaultTestFbsTableValueRoundTrip) {
  flatbuffers::FlatBufferBuilder fbb;
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
  auto table =
      flatbuffers::GetRoot<DefaultTestFbsTable>(fbb.GetBufferPointer());

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
  EXPECT_TRUE(new_table->e() == internal::TestFbsEnum_Second);
}

TEST(FlatbuffersTableImplTest, InitGeneratesSeeds) {
  flatbuffers::FlatBufferBuilder fbb;
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
  auto table =
      flatbuffers::GetRoot<DefaultTestFbsTable>(fbb.GetBufferPointer());

  auto domain = Arbitrary<DefaultTestFbsTable>();
  domain.WithSeeds({table});

  std::vector<Value<decltype(domain)>> values;
  absl::BitGen bitgen;
  values.reserve(1000);
  for (int i = 0; i < 1000; ++i) {
    Value value(domain, bitgen);
    values.push_back(std::move(value));
  }

  EXPECT_THAT(values,
              Contains(ResultOf(
                  [table](const auto& val) {
                    const auto is_str_eq = [](const flatbuffers::String* a,
                                              const flatbuffers::String* b) {
                      return a == nullptr && b == nullptr ||
                             a != nullptr && b != nullptr &&
                                 a->str() == b->str();
                    };

                    return (val.user_value->b() == table->b() &&
                            val.user_value->i8() == table->i8() &&
                            val.user_value->i16() == table->i16() &&
                            val.user_value->i32() == table->i32() &&
                            val.user_value->i64() == table->i64() &&
                            val.user_value->u8() == table->u8() &&
                            val.user_value->u16() == table->u16() &&
                            val.user_value->u32() == table->u32() &&
                            val.user_value->u64() == table->u64() &&
                            val.user_value->f() == table->f() &&
                            val.user_value->d() == table->d() &&
                            val.user_value->f() == table->f() &&
                            val.user_value->e() == table->e() &&
                            is_str_eq(val.user_value->str(), table->str()));
                  },
                  IsTrue())));
}

TEST(FlatbuffersTableImplTest, EventuallyMutatesAllTableFields) {
  auto domain = Arbitrary<DefaultTestFbsTable>();

  absl::BitGen bitgen;
  Value val(domain, bitgen);

  const auto verify_field_changes = [&](std::string_view name, auto get) {
    Set<decltype(get(val.user_value))> values;

    int iterations = 10'000;
    while (--iterations > 0 && values.size() < 2) {
      values.insert(get(val.user_value));
      val.Mutate(domain, bitgen, {}, false);
    }
    EXPECT_GT(iterations, 0)
        << "Field: " << name << " -- " << testing::PrintToString(values);
  };

  verify_field_changes("b", [](auto v) { return v->b(); });
  verify_field_changes("i8", [](auto v) { return v->i8(); });
  verify_field_changes("i16", [](auto v) { return v->i16(); });
  verify_field_changes("i32", [](auto v) { return v->i32(); });
  verify_field_changes("i64", [](auto v) { return v->i64(); });
  verify_field_changes("u8", [](auto v) { return v->u8(); });
  verify_field_changes("u16", [](auto v) { return v->u16(); });
  verify_field_changes("u32", [](auto v) { return v->u32(); });
  verify_field_changes("u64", [](auto v) { return v->u64(); });
  verify_field_changes("f", [](auto v) { return v->f(); });
  verify_field_changes("d", [](auto v) { return v->d(); });
  verify_field_changes("str", [](auto v) { return v->str()->str(); });
  verify_field_changes("e", [](auto v) { return v->e(); });
}

TEST(FlatbuffersTableImplTest, OptionalTestFbsTableEventuallyBecomeEmpty) {
  auto domain = Arbitrary<OptionalTestFbsTable>();

  absl::BitGen bitgen;
  Value val(domain, bitgen);

  const auto verify_field_becomes_null = [&](std::string_view name, auto has) {
    for (int i = 0; i < 10'000; ++i) {
      val.Mutate(domain, bitgen, {}, false);
      if (!has(val.user_value)) {
        break;
      }
    }
    EXPECT_FALSE(has(val.user_value)) << "Field never became unset: " << name;
  };

  verify_field_becomes_null("b", [](auto v) { return v->b().has_value(); });
  verify_field_becomes_null("i8", [](auto v) { return v->i8().has_value(); });
  verify_field_becomes_null("i16", [](auto v) { return v->i16().has_value(); });
  verify_field_becomes_null("i32", [](auto v) { return v->i32().has_value(); });
  verify_field_becomes_null("i64", [](auto v) { return v->i64().has_value(); });
  verify_field_becomes_null("u8", [](auto v) { return v->u8().has_value(); });
  verify_field_becomes_null("u16", [](auto v) { return v->u16().has_value(); });
  verify_field_becomes_null("u32", [](auto v) { return v->u32().has_value(); });
  verify_field_becomes_null("u64", [](auto v) { return v->u64().has_value(); });
  verify_field_becomes_null("f", [](auto v) { return v->f().has_value(); });
  verify_field_becomes_null("d", [](auto v) { return v->d().has_value(); });
  verify_field_becomes_null("str", [](auto v) { return v->str() != nullptr; });
  verify_field_becomes_null("e", [](auto v) { return v->e().has_value(); });
}

TEST(FlatbuffersTableImplTest, RequiredTestFbsTableFieldsAlwaysSet) {
  auto domain = Arbitrary<RequiredTestFbsTable>();

  absl::BitGen bitgen;
  Value val(domain, bitgen);

  const auto verify_field_always_set = [&](std::string_view name, auto has) {
    for (int i = 0; i < 10'000; ++i) {
      val.Mutate(domain, bitgen, {}, false);
      if (!has(val.user_value)) {
        break;
      }
    }
    EXPECT_TRUE(has(val.user_value)) << "Field is not set: " << name;
  };

  verify_field_always_set("str", [](auto v) { return v->str() != nullptr; });
}

}  // namespace
}  // namespace fuzztest
