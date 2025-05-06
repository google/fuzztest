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
#include "./fuzztest/test_flatbuffers_generated.h"

namespace fuzztest {
namespace {

using ::fuzztest::internal::NestedTestFbsTable;
using ::fuzztest::internal::OptionalRequiredTestFbsTable;
using ::fuzztest::internal::SimpleTestFbsTable;
using ::testing::Contains;
using ::testing::IsTrue;
using ::testing::ResultOf;

TEST(FlatbuffersMetaTest, IsFlatbuffersTable) {
  static_assert(internal::is_flatbuffers_table_v<SimpleTestFbsTable>);
  static_assert(!internal::is_flatbuffers_table_v<int>);
}

TEST(FlatbuffersTableDomainImplTest, SimpleTestFbsTableValueRoundTrip) {
  auto domain = Arbitrary<SimpleTestFbsTable>();

  flatbuffers::FlatBufferBuilder fbb;
  auto table_offset = internal::CreateSimpleTestFbsTableDirect(
      fbb, true, 1.0, "foo bar baz", internal::TestFbsEnum_Second);
  fbb.Finish(table_offset);
  auto table = flatbuffers::GetRoot<SimpleTestFbsTable>(fbb.GetBufferPointer());

  auto corpus = domain.FromValue(table);
  ASSERT_TRUE(corpus.has_value());
  ASSERT_OK(domain.ValidateCorpusValue(*corpus));

  auto ir = domain.SerializeCorpus(corpus.value());

  auto new_corpus = domain.ParseCorpus(ir);
  ASSERT_TRUE(new_corpus.has_value());
  ASSERT_OK(domain.ValidateCorpusValue(*new_corpus));

  auto new_table = domain.GetValue(*new_corpus);
  EXPECT_EQ(new_table->b(), true);
  EXPECT_EQ(new_table->f(), 1.0);
  EXPECT_EQ(new_table->str()->str(), "foo bar baz");
  EXPECT_TRUE(new_table->e() == internal::TestFbsEnum_Second);
}

TEST(FlatbuffersTableDomainImplTest, InitGeneratesSeeds) {
  auto domain = Arbitrary<SimpleTestFbsTable>();

  flatbuffers::FlatBufferBuilder fbb;
  auto table_offset = internal::CreateSimpleTestFbsTableDirect(
      fbb, true, 1.0, "foo bar baz", internal::TestFbsEnum_Second);
  fbb.Finish(table_offset);
  auto table = flatbuffers::GetRoot<SimpleTestFbsTable>(fbb.GetBufferPointer());

  domain.WithSeeds({table});

  std::vector<Value<decltype(domain)>> values;
  absl::BitGen bitgen;
  values.reserve(1000);
  for (int i = 0; i < 1000; ++i) {
    Value value(domain, bitgen);
    values.push_back(std::move(value));
  }

  EXPECT_THAT(
      values,
      Contains(ResultOf(
          [table](const auto& val) {
            bool has_same_str =
                val.user_value->str() == nullptr && table->str() == nullptr;
            if (val.user_value->str() != nullptr && table->str() != nullptr) {
              has_same_str =
                  val.user_value->str()->str() == table->str()->str();
            }
            return (val.user_value->b() == table->b() &&
                    val.user_value->f() == table->f() &&
                    val.user_value->e() == table->e() && has_same_str);
          },
          IsTrue())));
}

TEST(FlatbuffersTableDomainImplTest, EventuallyMutatesAllTableFields) {
  auto domain = Arbitrary<SimpleTestFbsTable>();

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
  verify_field_changes("f", [](auto v) { return v->f(); });
  verify_field_changes("str",
                       [](auto v) { return v->str() ? v->str()->str() : ""; });
  verify_field_changes("e", [](auto v) { return v->e(); });
}

TEST(FlatbuffersTableDomainImplTest, OptionalFieldsEventuallyBecomeEmpty) {
  auto domain = Arbitrary<OptionalRequiredTestFbsTable>();

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

  verify_field_becomes_null("opt_scalar",
                            [](auto v) { return v->opt_scalar().has_value(); });
  verify_field_becomes_null("opt_str",
                            [](auto v) { return v->opt_str() != nullptr; });
}

TEST(FlatbuffersTableDomainImplTest, DefaultAndRequiredFieldsAlwaysSet) {
  auto domain = Arbitrary<OptionalRequiredTestFbsTable>();

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

  verify_field_always_set("def_scalar", [](auto v) { return true; });
  verify_field_always_set("req_str",
                          [](auto v) { return v->req_str() != nullptr; });
}

TEST(FlatbuffersTableDomainImplTest, NestedTableValueRoundTrip) {
  auto domain = Arbitrary<NestedTestFbsTable>();
  absl::BitGen bitgen;
  Value val(domain, bitgen);

  flatbuffers::FlatBufferBuilder fbb;
  auto child_offset = internal::CreateSimpleTestFbsTableDirect(
      fbb, true, 1.0, "foo bar baz", internal::TestFbsEnum_Second);
  auto parent_offset = internal::CreateNestedTestFbsTable(fbb, child_offset);
  fbb.Finish(parent_offset);
  auto table = flatbuffers::GetRoot<NestedTestFbsTable>(fbb.GetBufferPointer());

  auto parent_corpus = domain.FromValue(table);
  ASSERT_TRUE(parent_corpus.has_value());

  auto ir = domain.SerializeCorpus(parent_corpus.value());

  auto new_corpus = domain.ParseCorpus(ir);
  ASSERT_TRUE(new_corpus.has_value());
  ASSERT_OK(domain.ValidateCorpusValue(*new_corpus));

  auto new_table = domain.GetValue(parent_corpus.value());
  EXPECT_NE(new_table->t(), nullptr);
  EXPECT_EQ(new_table->t()->b(), true);
  EXPECT_EQ(new_table->t()->f(), 1.0);
  EXPECT_NE(new_table->t()->str(), nullptr);
  EXPECT_EQ(new_table->t()->str()->str(), "foo bar baz");
  EXPECT_TRUE(new_table->t()->e() == internal::TestFbsEnum_Second);
}

TEST(FlatbuffersTableDomainImplTest, EventuallyMutatesAllNestedTableFields) {
  auto domain = Arbitrary<NestedTestFbsTable>();
  absl::BitGen bitgen;
  Value val(domain, bitgen);

  const auto verify_field_changes = [&](std::string_view name, auto get) {
    Set<typename decltype(get(val.user_value))::value_type> values;

    int iterations = 10'000;
    while (--iterations > 0 && values.size() < 2) {
      auto value = get(val.user_value);
      if (value.has_value()) {
        values.insert(*value);
      }
      val.Mutate(domain, bitgen, {}, false);
    }
    EXPECT_GT(iterations, 0)
        << "Field: " << name << " -- " << testing::PrintToString(values);
  };

  verify_field_changes("t.b", [](auto v) {
    return v->t() ? std::make_optional(v->t()->b()) : std::nullopt;
  });
  verify_field_changes("t.f", [](auto v) {
    return v->t() ? std::make_optional(v->t()->f()) : std::nullopt;
  });
  verify_field_changes("t.str", [](auto v) {
    return v->t() ? v->t()->str() ? std::make_optional(v->t()->str()->str())
                                  : std::nullopt
                  : std::nullopt;
  });
  verify_field_changes("t.e", [](auto v) {
    return v->t() ? std::make_optional(v->t()->e()) : std::nullopt;
  });
}

}  // namespace
}  // namespace fuzztest
