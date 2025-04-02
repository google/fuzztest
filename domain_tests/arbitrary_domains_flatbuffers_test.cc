#include <cstdint>
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
#include "flatbuffers/reflection.h"
#include "flatbuffers/reflection_generated.h"
#include "flatbuffers/string.h"
#include "flatbuffers/table.h"
#include "flatbuffers/verifier.h"
#include "./fuzztest/domain.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/domains/flatbuffers_domain_impl.h"
#include "./fuzztest/test_flatbuffers_generated.h"

namespace fuzztest {
namespace {
using internal::OptionalRequiredTestFbsTable;
using internal::SimpleTestFbsTable;
using ::testing::Contains;
using ::testing::IsTrue;
using ::testing::ResultOf;

TEST(FlatbuffersTableImplTest, TypeGetters) {
  ::testing::StaticAssertTypeEq<reflection::Object,
                                internal::get_object_t<reflection::Schema>>();
  ::testing::StaticAssertTypeEq<reflection::Field,
                                internal::get_field_t<reflection::Object>>();
  ::testing::StaticAssertTypeEq<flatbuffers::String,
                                internal::get_string_t<reflection::Object>>();
  ::testing::StaticAssertTypeEq<flatbuffers::Offset<reflection::Field>,
                                internal::get_offset_t<reflection::Object>>();
  ::testing::StaticAssertTypeEq<reflection::BaseType,
                                internal::get_base_type_t<reflection::Field>>();
  ::testing::StaticAssertTypeEq<flatbuffers::FlatBufferBuilder,
                                internal::get_builder_t<SimpleTestFbsTable>>();
  ::testing::StaticAssertTypeEq<flatbuffers::uoffset_t,
                                internal::get_uoffset_t<reflection::Object>>();
  ::testing::StaticAssertTypeEq<uint16_t,
                                internal::get_field_id_t<reflection::Field>>();
}

TEST(FlatbuffersTableImplTest, SimpleTestFbsTableValueRoundTrip) {
  auto domain =
      internal::FlatbuffersTableImpl<SimpleTestFbsTable, flatbuffers::Table,
                                     reflection::Schema, flatbuffers::Verifier>{
          reflection::GetSchema, reflection::VerifySchemaBuffer,
          flatbuffers::GetTypeSize, flatbuffers::GetRoot<SimpleTestFbsTable>};

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

TEST(FlatbuffersTableImplTest, InitGeneratesSeeds) {
  auto domain =
      internal::FlatbuffersTableImpl<SimpleTestFbsTable, flatbuffers::Table,
                                     reflection::Schema, flatbuffers::Verifier>{
          reflection::GetSchema, reflection::VerifySchemaBuffer,
          flatbuffers::GetTypeSize, flatbuffers::GetRoot<SimpleTestFbsTable>};

  flatbuffers::FlatBufferBuilder fbb;
  auto table_offset = internal::CreateSimpleTestFbsTableDirect(
      fbb, true, 1.0, "foo bar baz", internal::TestFbsEnum_Second);
  fbb.Finish(table_offset);
  auto table = flatbuffers::GetRoot<SimpleTestFbsTable>(fbb.GetBufferPointer());

  domain = domain.WithSeeds({table});

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

TEST(FlatbuffersTableImplTest, EventuallyMutatesAllTableFields) {
  auto domain =
      internal::FlatbuffersTableImpl<SimpleTestFbsTable, flatbuffers::Table,
                                     reflection::Schema, flatbuffers::Verifier>{
          reflection::GetSchema, reflection::VerifySchemaBuffer,
          flatbuffers::GetTypeSize, flatbuffers::GetRoot<SimpleTestFbsTable>};

  absl::BitGen bitgen;
  Value val(domain, bitgen);

  const auto verify_field_changes = [&](std::string_view name, auto has,
                                        auto get) {
    Set<decltype(get(val.user_value))> values;

    int iterations = 10'000;
    while (--iterations > 0 && values.size() < 2) {
      values.insert(get(val.user_value));
      val.Mutate(domain, bitgen, {}, false);
    }
    EXPECT_GT(iterations, 0)
        << "Field: " << name << " -- " << testing::PrintToString(values);
  };

  verify_field_changes(
      "b", [](auto v) { return true; }, [](auto v) { return v->b(); });
  verify_field_changes(
      "f", [](auto v) { return true; }, [](auto v) { return v->f(); });
  verify_field_changes(
      "str", [](auto v) { return v->str() != nullptr; },
      [](auto v) { return v->str()->str(); });
  verify_field_changes(
      "e", [](auto v) { return true; }, [](auto v) { return v->e(); });
}

TEST(FlatbuffersTableImplTest, OptionalFieldsEventuallyBecomeEmpty) {
  auto domain =
      internal::FlatbuffersTableImpl<OptionalRequiredTestFbsTable,
                                     flatbuffers::Table, reflection::Schema,
                                     flatbuffers::Verifier>{
          reflection::GetSchema, reflection::VerifySchemaBuffer,
          flatbuffers::GetTypeSize,
          flatbuffers::GetRoot<OptionalRequiredTestFbsTable>};

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

TEST(FlatbuffersTableImplTest, DefaultAndRequiredFieldsAlwaysSet) {
  auto domain =
      internal::FlatbuffersTableImpl<OptionalRequiredTestFbsTable,
                                     flatbuffers::Table, reflection::Schema,
                                     flatbuffers::Verifier>{
          reflection::GetSchema, reflection::VerifySchemaBuffer,
          flatbuffers::GetTypeSize,
          flatbuffers::GetRoot<OptionalRequiredTestFbsTable>};

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
}  // namespace
}  // namespace fuzztest
