#include <cstdint>
#include <optional>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
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
#include "./fuzztest/test_flatbuffers_generated.h"

namespace fuzztest {
namespace {

using ::fuzztest::internal::NestedTestFbsTable;
using ::fuzztest::internal::OptionalRequiredTestFbsTable;
using ::fuzztest::internal::SimpleTestFbsTable;
using ::fuzztest::internal::TestFbsEnum;
using ::fuzztest::internal::UnionTestFbsTable;
using ::fuzztest::internal::VectorsTestFbsTable;
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

TEST(FlatbuffersTableDomainImplTest, VectorsSerializeAndDeserialize) {
  auto domain = Arbitrary<VectorsTestFbsTable>();

  absl::BitGen bitgen;
  Value val(domain, bitgen);

  flatbuffers::FlatBufferBuilder fbb;
  std::vector<flatbuffers::Offset<flatbuffers::String>> str_offsets;
  for (const auto& str : {"foo", "bar", "baz"}) {
    str_offsets.push_back(fbb.CreateString(str));
  }
  std::vector<flatbuffers::Offset<SimpleTestFbsTable>> table_offsets;
  for (const auto& str : {"foo", "bar", "baz"}) {
    table_offsets.push_back(internal::CreateSimpleTestFbsTableDirect(
        fbb, true, 1.0, str, internal::TestFbsEnum_Second));
  }
  std::vector<uint8_t> b{true, false};
  std::vector<int8_t> i8{1, 2, 3};
  std::vector<int16_t> i16{1, 2, 3};
  std::vector<int32_t> i32{1, 2, 3};
  std::vector<int64_t> i64{1, 2, 3};
  std::vector<uint8_t> u8{1, 2, 3};
  std::vector<uint16_t> u16{1, 2, 3};
  std::vector<uint32_t> u32{1, 2, 3};
  std::vector<uint64_t> u64{1, 2, 3};
  std::vector<float> f{1, 2, 3};
  std::vector<double> d{1, 2, 3};
  std::vector<std::underlying_type_t<TestFbsEnum>> e{
      TestFbsEnum::TestFbsEnum_First, TestFbsEnum::TestFbsEnum_Second,
      TestFbsEnum::TestFbsEnum_Third};
  auto table_offset = internal::CreateVectorsTestFbsTableDirect(
      fbb, &b, &i8, &i16, &i32, &i64, &u8, &u16, &u32, &u64, &f, &d,
      &str_offsets, &e, &table_offsets);
  fbb.Finish(table_offset);
  auto table =
      flatbuffers::GetRoot<VectorsTestFbsTable>(fbb.GetBufferPointer());

  auto corpus = domain.FromValue(table);
  auto ir = domain.SerializeCorpus(corpus.value());
  {
    auto new_corpus = domain.ParseCorpus(ir);
    ASSERT_TRUE(new_corpus.has_value());
    ASSERT_OK(domain.ValidateCorpusValue(*new_corpus));

    auto new_table = domain.GetValue(*new_corpus);
    ASSERT_NE(new_table, nullptr);
    ASSERT_NE(new_table->b(), nullptr);
    EXPECT_EQ(new_table->b()->size(), 2);
    EXPECT_EQ(new_table->b()->Get(0), true);
    EXPECT_EQ(new_table->b()->Get(1), false);
    ASSERT_NE(new_table->i8(), nullptr);
    EXPECT_EQ(new_table->i8()->size(), 3);
    EXPECT_EQ(new_table->i8()->Get(0), 1);
    EXPECT_EQ(new_table->i8()->Get(1), 2);
    EXPECT_EQ(new_table->i8()->Get(2), 3);
    ASSERT_NE(new_table->i16(), nullptr);
    EXPECT_EQ(new_table->i16()->size(), 3);
    EXPECT_EQ(new_table->i16()->Get(0), 1);
    EXPECT_EQ(new_table->i16()->Get(1), 2);
    EXPECT_EQ(new_table->i16()->Get(2), 3);
    ASSERT_NE(new_table->i32(), nullptr);
    EXPECT_EQ(new_table->i32()->size(), 3);
    EXPECT_EQ(new_table->i32()->Get(0), 1);
    EXPECT_EQ(new_table->i32()->Get(1), 2);
    EXPECT_EQ(new_table->i32()->Get(2), 3);
    ASSERT_NE(new_table->i64(), nullptr);
    EXPECT_EQ(new_table->i64()->size(), 3);
    EXPECT_EQ(new_table->i64()->Get(0), 1);
    EXPECT_EQ(new_table->i64()->Get(1), 2);
    EXPECT_EQ(new_table->i64()->Get(2), 3);
    ASSERT_NE(new_table->u8(), nullptr);
    EXPECT_EQ(new_table->u8()->size(), 3);
    EXPECT_EQ(new_table->u8()->Get(0), 1);
    EXPECT_EQ(new_table->u8()->Get(1), 2);
    EXPECT_EQ(new_table->u8()->Get(2), 3);
    ASSERT_NE(new_table->u16(), nullptr);
    EXPECT_EQ(new_table->u16()->size(), 3);
    EXPECT_EQ(new_table->u16()->Get(0), 1);
    EXPECT_EQ(new_table->u16()->Get(1), 2);
    EXPECT_EQ(new_table->u16()->Get(2), 3);
    ASSERT_NE(new_table->u32(), nullptr);
    EXPECT_EQ(new_table->u32()->size(), 3);
    EXPECT_EQ(new_table->u32()->Get(0), 1);
    EXPECT_EQ(new_table->u32()->Get(1), 2);
    EXPECT_EQ(new_table->u32()->Get(2), 3);
    ASSERT_NE(new_table->u64(), nullptr);
    EXPECT_EQ(new_table->u64()->size(), 3);
    EXPECT_EQ(new_table->u64()->Get(0), 1);
    EXPECT_EQ(new_table->u64()->Get(1), 2);
    EXPECT_EQ(new_table->u64()->Get(2), 3);
    ASSERT_NE(new_table->f(), nullptr);
    EXPECT_EQ(new_table->f()->size(), 3);
    EXPECT_EQ(new_table->f()->Get(0), 1);
    EXPECT_EQ(new_table->f()->Get(1), 2);
    EXPECT_EQ(new_table->f()->Get(2), 3);
    ASSERT_NE(new_table->d(), nullptr);
    EXPECT_EQ(new_table->d()->size(), 3);
    EXPECT_EQ(new_table->d()->Get(0), 1);
    EXPECT_EQ(new_table->d()->Get(1), 2);
    EXPECT_EQ(new_table->d()->Get(2), 3);
    ASSERT_NE(new_table->e(), nullptr);
    EXPECT_EQ(new_table->e()->size(), 3);
    EXPECT_EQ(new_table->e()->Get(0), internal::TestFbsEnum_First);
    EXPECT_EQ(new_table->e()->Get(1), internal::TestFbsEnum_Second);
    EXPECT_EQ(new_table->e()->Get(2), internal::TestFbsEnum_Third);
    EXPECT_EQ(new_table->str()->size(), 3);
    EXPECT_EQ(new_table->str()->Get(0)->str(), "foo");
    EXPECT_EQ(new_table->str()->Get(1)->str(), "bar");
    EXPECT_EQ(new_table->str()->Get(2)->str(), "baz");
    ASSERT_NE(new_table->t(), nullptr);
    EXPECT_EQ(new_table->t()->size(), 3);
    EXPECT_EQ(new_table->t()->Get(0)->b(), true);
    EXPECT_EQ(new_table->t()->Get(1)->b(), true);
    EXPECT_EQ(new_table->t()->Get(2)->b(), true);
    EXPECT_EQ(new_table->t()->Get(0)->f(), 1.0);
    EXPECT_EQ(new_table->t()->Get(1)->f(), 1.0);
    EXPECT_EQ(new_table->t()->Get(2)->f(), 1.0);
    EXPECT_EQ(new_table->t()->Get(0)->str()->str(), "foo");
    EXPECT_EQ(new_table->t()->Get(1)->str()->str(), "bar");
    EXPECT_EQ(new_table->t()->Get(2)->str()->str(), "baz");
    EXPECT_EQ(new_table->t()->Get(0)->e(), internal::TestFbsEnum_Second);
    EXPECT_EQ(new_table->t()->Get(1)->e(), internal::TestFbsEnum_Second);
    EXPECT_EQ(new_table->t()->Get(2)->e(), internal::TestFbsEnum_Second);
  }
}

TEST(FlatbuffersTableDomainImplTest, EventuallyMutatesAllVectorFields) {
  auto domain = Arbitrary<VectorsTestFbsTable>();

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
    return v && v->t() ? std::make_optional(v->b()) : std::nullopt;
  });
  verify_field_changes("t.i8", [](auto v) {
    return v && v->i8() ? std::make_optional(v->i8()) : std::nullopt;
  });
  verify_field_changes("t.i16", [](auto v) {
    return v && v->i16() ? std::make_optional(v->i16()) : std::nullopt;
  });
  verify_field_changes("t.i32", [](auto v) {
    return v && v->i32() ? std::make_optional(v->i32()) : std::nullopt;
  });
  verify_field_changes("t.i64", [](auto v) {
    return v && v->i64() ? std::make_optional(v->i64()) : std::nullopt;
  });
  verify_field_changes("t.u8", [](auto v) {
    return v && v->u8() ? std::make_optional(v->u8()) : std::nullopt;
  });
  verify_field_changes("t.u16", [](auto v) {
    return v && v->u16() ? std::make_optional(v->u16()) : std::nullopt;
  });
  verify_field_changes("t.u32", [](auto v) {
    return v && v->u32() ? std::make_optional(v->u32()) : std::nullopt;
  });
  verify_field_changes("t.u64", [](auto v) {
    return v && v->u64() ? std::make_optional(v->u64()) : std::nullopt;
  });
  verify_field_changes("t.f", [](auto v) {
    return v && v->f() ? std::make_optional(v->f()) : std::nullopt;
  });
  verify_field_changes("t.d", [](auto v) {
    return v && v->d() ? std::make_optional(v->d()) : std::nullopt;
  });
  verify_field_changes("t.e", [](auto v) {
    return v && v->e() ? std::make_optional(v->e()) : std::nullopt;
  });
  verify_field_changes("t.str", [](auto v) {
    return v && v->str() ? std::make_optional(v->str()) : std::nullopt;
  });
  verify_field_changes("t.t", [](auto v) {
    return v && v->t() ? std::make_optional(v->t()) : std::nullopt;
  });
}

TEST(FlatbuffersTableDomainImplTest, UnionFieldsSerializeAndDeserialize) {
  flatbuffers::FlatBufferBuilder fbb;
  auto child_table_offset = internal::CreateSimpleTestFbsTableDirect(
      fbb, true, 1.0, "foo bar baz", internal::TestFbsEnum_Second);
  auto vec_child_one = internal::CreateSimpleTestFbsTableDirect(
      fbb, true, 1.0, "foo bar baz", internal::TestFbsEnum_Second);
  auto vec_child_two = internal::CreateOptionalRequiredTestFbsTableDirect(
      fbb, true, std::nullopt, "foo bar baz");
  auto vec_types =
      fbb.CreateVector<uint8_t>({internal::Union_SimpleTestFbsTable,
                                 internal::Union_OptionalRequiredTestFbsTable});
  auto vec_values =
      fbb.CreateVector({vec_child_one.Union(), vec_child_two.Union()});
  auto parent_offset = internal::CreateUnionTestFbsTable(
      fbb, internal::Union_SimpleTestFbsTable, child_table_offset.Union(),
      vec_types, vec_values);
  fbb.Finish(parent_offset);
  auto table = flatbuffers::GetRoot<UnionTestFbsTable>(fbb.GetBufferPointer());

  auto domain = Arbitrary<UnionTestFbsTable>();
  auto corpus = domain.FromValue(table);
  auto ir = domain.SerializeCorpus(*corpus);
  auto new_corpus = domain.ParseCorpus(ir);
  ASSERT_TRUE(new_corpus.has_value());
  ASSERT_OK(domain.ValidateCorpusValue(*new_corpus));
  auto new_table = domain.GetValue(*new_corpus);
  ASSERT_NE(new_table, nullptr);
  ASSERT_NE(new_table->u(), nullptr);
  ASSERT_NE(new_table->u_as_SimpleTestFbsTable(), nullptr);
  EXPECT_EQ(new_table->u_as_SimpleTestFbsTable()->b(), true);
  EXPECT_EQ(new_table->u_as_SimpleTestFbsTable()->f(), 1.0);
  EXPECT_EQ(new_table->u_as_SimpleTestFbsTable()->str()->str(), "foo bar baz");
  EXPECT_EQ(new_table->u_as_SimpleTestFbsTable()->e(),
            internal::TestFbsEnum_Second);

  ASSERT_NE(new_table->u_vec(), nullptr);
  ASSERT_EQ(new_table->u_vec()->size(), 2);
  auto u_vec_one =
      static_cast<const SimpleTestFbsTable*>(new_table->u_vec()->Get(0));
  ASSERT_NE(u_vec_one, nullptr);
  EXPECT_EQ(u_vec_one->b(), true);
  EXPECT_EQ(u_vec_one->f(), 1.0);
  EXPECT_EQ(u_vec_one->str()->str(), "foo bar baz");
  EXPECT_EQ(u_vec_one->e(), internal::TestFbsEnum_Second);

  auto u_vec_two = static_cast<const OptionalRequiredTestFbsTable*>(
      new_table->u_vec()->Get(1));
  ASSERT_NE(u_vec_two, nullptr);
  EXPECT_EQ(u_vec_two->def_scalar(), true);
  EXPECT_EQ(u_vec_two->opt_scalar(), std::nullopt);
  ASSERT_NE(u_vec_two->req_str(), nullptr);
  EXPECT_EQ(u_vec_two->req_str()->str(), "foo bar baz");
  EXPECT_EQ(u_vec_two->opt_str(), nullptr);
}

TEST(FlatbuffersTableDomainImplTest, UnionFieldsEventuallyMutate) {
  auto domain = Arbitrary<UnionTestFbsTable>();

  absl::BitGen bitgen;
  Value val(domain, bitgen);

  const auto verify_field_changes = [&](std::string_view name, auto get) {
    Set<decltype(get(val.user_value))> values;

    int iterations = 10'000;
    while (--iterations > 0 && values.size() < 2) {
      auto value = get(val.user_value);
      values.insert(value);
      val.Mutate(domain, bitgen, {}, false);
    }
    EXPECT_GT(iterations, 0)
        << "Field: " << name << " -- " << testing::PrintToString(values);
  };

  verify_field_changes("u_type", [](auto v) { return v->u_type(); });
  verify_field_changes("u_as_SimpleTestFbsTable",
                       [](auto v) { return v->u_as_SimpleTestFbsTable(); });
  verify_field_changes("u_as_OptionalRequiredTestFbsTable", [](auto v) {
    return v->u_as_OptionalRequiredTestFbsTable();
  });
  verify_field_changes("u_vec_type", [](auto v) { return v->u_vec_type(); });
  verify_field_changes("u_vec", [](auto v) { return v->u_vec(); });
  verify_field_changes("u_vec[0].as_SimpleTestFbsTable", [](auto v) {
    return v->u_vec() && v->u_vec()->size() > 0 &&
                   v->u_vec_type()->Get(0) == internal::Union_SimpleTestFbsTable
               ? static_cast<const SimpleTestFbsTable*>(v->u_vec()->Get(0))
               : nullptr;
  });
  verify_field_changes("u_vec[0].as_OptionalRequiredTestFbsTable", [](auto v) {
    return v->u_vec() && v->u_vec()->size() > 0 &&
                   v->u_vec_type()->Get(0) ==
                       internal::Union_OptionalRequiredTestFbsTable
               ? static_cast<const OptionalRequiredTestFbsTable*>(
                     v->u_vec()->Get(0))
               : nullptr;
  });
}

}  // namespace
}  // namespace fuzztest
