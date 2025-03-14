#include <cstddef>
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
using internal::NestedTestFbsTable;
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
  ::testing::StaticAssertTypeEq<reflection::BaseType,
                                internal::get_base_type_t<reflection::Field>>();
  ::testing::StaticAssertTypeEq<flatbuffers::FlatBufferBuilder,
                                internal::get_builder_t<SimpleTestFbsTable>>();
  ::testing::StaticAssertTypeEq<uint16_t,
                                internal::get_field_id_t<reflection::Field>>();
}

struct FlatbuffersToolbox {
  using base_type = reflection::BaseType;
  using builder_type = flatbuffers::FlatBufferBuilder;
  using schema_type = reflection::Schema;
  using table_type = flatbuffers::Table;
  using verifier_type = flatbuffers::Verifier;
  template <typename T = void>
  using offset_type = flatbuffers::Offset<T>;

  static size_t GetTypeSize(const base_type& type) {
    return flatbuffers::GetTypeSize(type);
  }

  template <typename T>
  static const T* GetRoot(const void* buf) {
    return flatbuffers::GetRoot<T>(buf);
  }

  static bool VerifySchemaBuffer(verifier_type& verifier) {
    return reflection::VerifySchemaBuffer(verifier);
  }
};

TEST(FlatbuffersTableDomainImplTest, SimpleTestFbsTableValueRoundTrip) {
  auto domain = internal::FlatbuffersTableDomainImpl<SimpleTestFbsTable,
                                                     FlatbuffersToolbox>{};

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
  auto domain = internal::FlatbuffersTableDomainImpl<SimpleTestFbsTable,
                                                     FlatbuffersToolbox>{};

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
  auto domain = internal::FlatbuffersTableDomainImpl<SimpleTestFbsTable,
                                                     FlatbuffersToolbox>{};

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

TEST(FlatbuffersTableImplTest, OptionalFieldsEventuallyBecomeEmpty) {
  auto domain =
      internal::FlatbuffersTableDomainImpl<OptionalRequiredTestFbsTable,
                                           FlatbuffersToolbox>{};

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
      internal::FlatbuffersTableDomainImpl<OptionalRequiredTestFbsTable,
                                           FlatbuffersToolbox>{};

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
  auto domain = internal::FlatbuffersTableDomainImpl<NestedTestFbsTable,
                                                     FlatbuffersToolbox>{};

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
  auto domain = internal::FlatbuffersTableDomainImpl<NestedTestFbsTable,
                                                     FlatbuffersToolbox>{};

  absl::BitGen bitgen;
  Value val(domain, bitgen);

  const auto verify_field_changes = [&](std::string_view name, auto get) {
    Set<std::optional<decltype(get(val.user_value))>> values;

    int iterations = 10'000;
    while (--iterations > 0 && values.size() < 2) {
      auto value = get(val.user_value);
      values.insert(value);
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
