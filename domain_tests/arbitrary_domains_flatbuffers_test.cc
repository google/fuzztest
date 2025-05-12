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
#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/random/random.h"
#include "flatbuffers/base.h"
#include "flatbuffers/buffer.h"
#include "flatbuffers/flatbuffer_builder.h"
#include "flatbuffers/string.h"
#include "flatbuffers/vector.h"
#include "flatbuffers/verifier.h"
#include "./fuzztest/domain.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/flatbuffers.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/test_flatbuffers_generated.h"

namespace fuzztest {
namespace {

using ::fuzztest::internal::BoolStruct;
using ::fuzztest::internal::BoolTable;
using ::fuzztest::internal::DefaultStruct;
using ::fuzztest::internal::DefaultTable;
using ::fuzztest::internal::Enum;
using ::fuzztest::internal::OptionalTable;
using ::fuzztest::internal::RequiredTable;
using ::fuzztest::internal::StringTable;
using ::fuzztest::internal::UnionTable;
using ::testing::_;
using ::testing::Contains;
using ::testing::Each;
using ::testing::IsTrue;
using ::testing::NotNull;
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

template <>
inline bool Eq<BoolStruct>(BoolStruct rhs, BoolStruct lhs) {
  return Eq(rhs.b(), lhs.b());
};

template <>
inline bool Eq<const DefaultStruct*>(const DefaultStruct* rhs,
                                     const DefaultStruct* lhs) {
  if (rhs == nullptr && lhs == nullptr) {
    return true;
  } else if (rhs == nullptr || lhs == nullptr) {
    return false;
  } else {
    return Eq(rhs->b(), lhs->b()) && Eq(rhs->i8(), lhs->i8()) &&
           Eq(rhs->i16(), lhs->i16()) && Eq(rhs->i32(), lhs->i32()) &&
           Eq(rhs->i64(), lhs->i64()) && Eq(rhs->u8(), lhs->u8()) &&
           Eq(rhs->u16(), lhs->u16()) && Eq(rhs->u32(), lhs->u32()) &&
           Eq(rhs->u64(), lhs->u64()) && Eq(rhs->f(), lhs->f()) &&
           Eq(rhs->d(), lhs->d()) && Eq(rhs->e(), lhs->e()) &&
           Eq(rhs->s(), lhs->s());
  }
}

template <>
inline bool Eq<const BoolTable*>(const BoolTable* rhs, const BoolTable* lhs) {
  return (rhs == nullptr && lhs == nullptr) ||
         (rhs != nullptr && lhs != nullptr && rhs->b() == lhs->b());
};

template <>
inline bool Eq<std::pair<uint8_t, const void*>>(
    std::pair<uint8_t, const void*> rhs, std::pair<uint8_t, const void*> lhs) {
  if (rhs.first == internal::Union_NONE && lhs.first == internal::Union_NONE) {
    return true;
  } else if (rhs.first != lhs.first) {
    return false;
  } else {
    switch (rhs.first) {
      case internal::Union_BoolTable:
        return static_cast<const BoolTable*>(rhs.second)->b() ==
               static_cast<const BoolTable*>(lhs.second)->b();
      case internal::Union_StringTable:
        return static_cast<const StringTable*>(rhs.second)->str()->str() ==
               static_cast<const StringTable*>(lhs.second)->str()->str();
      case internal::Union_BoolStruct:
        return static_cast<const BoolStruct*>(rhs.second)->b() ==
               static_cast<const BoolStruct*>(lhs.second)->b();
      default:
        CHECK(false) << "Unsupported union type";
    }
  }
}

template <typename T>
inline bool VectorEq(const flatbuffers::Vector<T>* rhs,
                     const flatbuffers::Vector<T>* lhs) {
  if (rhs == nullptr && lhs == nullptr) {
    return true;
  } else if (rhs == nullptr || lhs == nullptr) {
    return false;
  }
  if (rhs->size() != lhs->size()) {
    return false;
  }
  for (int i = 0; i < rhs->size(); ++i) {
    if (!Eq(rhs->Get(i), lhs->Get(i))) {
      return false;
    }
  }
  return true;
};

inline bool VectorUnionEq(
    const flatbuffers::Vector<uint8_t>* rhs_type,
    const flatbuffers::Vector<::flatbuffers::Offset<void>>* rhs,
    const flatbuffers::Vector<uint8_t>* lhs_type,
    const flatbuffers::Vector<::flatbuffers::Offset<void>>* lhs) {
  if (!VectorEq(rhs_type, lhs_type)) {
    return false;
  }
  if (rhs == nullptr && lhs == nullptr) {
    return true;
  } else if (rhs == nullptr || lhs == nullptr) {
    return false;
  }
  if (rhs->size() != lhs->size()) {
    return false;
  }
  for (int i = 0; i < rhs->size(); ++i) {
    if (!Eq(std::make_pair(rhs_type->Get(i), rhs->Get(i)),
            std::make_pair(lhs_type->Get(i), lhs->Get(i)))) {
      return false;
    }
  }
  return true;
};

const internal::DefaultTable* CreateDefaultTable(
    flatbuffers::FlatBufferBuilder& fbb) {
  auto bool_table_offset = internal::CreateBoolTable(fbb, true);
  auto string_table_offset =
      internal::CreateStringTableDirect(fbb, "foo bar baz");
  DefaultStruct s{
      true,                   // b
      1,                      // i8
      2,                      // i16
      3,                      // i32
      4,                      // i64
      5,                      // u8
      6,                      // u16
      7,                      // u32
      8,                      // u64
      9,                      // f
      10.0,                   // d
      internal::Enum_Second,  // e
      BoolStruct{true}        // s
  };
  std::vector<uint8_t> v_b{true, false};
  std::vector<int8_t> v_i8{1, 2, 3};
  std::vector<int16_t> v_i16{1, 2, 3};
  std::vector<int32_t> v_i32{1, 2, 3};
  std::vector<int64_t> v_i64{1, 2, 3};
  std::vector<uint8_t> v_u8{1, 2, 3};
  std::vector<uint16_t> v_u16{1, 2, 3};
  std::vector<uint32_t> v_u32{1, 2, 3};
  std::vector<uint64_t> v_u64{1, 2, 3};
  std::vector<float> v_f{1, 2, 3};
  std::vector<double> v_d{1, 2, 3};
  std::vector<flatbuffers::Offset<flatbuffers::String>> v_str{
      fbb.CreateString("foo"), fbb.CreateString("bar"),
      fbb.CreateString("baz")};
  std::vector<std::underlying_type_t<internal::Enum>> v_e{
      internal::Enum_First, internal::Enum_Second, internal::Enum_Third};
  std::vector<flatbuffers::Offset<BoolTable>> v_t{bool_table_offset};
  std::vector<std::underlying_type_t<internal::Union>> v_u_type{
      internal::Union_BoolTable,
      internal::Union_StringTable,
  };
  std::vector<flatbuffers::Offset<>> v_u{
      bool_table_offset.Union(),
      string_table_offset.Union(),
  };
  std::vector<DefaultStruct> v_s{s};
  auto table_offset =
      internal::CreateDefaultTableDirect(fbb,
                                         true,                       // b
                                         1,                          // i8
                                         2,                          // i16
                                         3,                          // i32
                                         4,                          // i64
                                         5,                          // u8
                                         6,                          // u16
                                         7,                          // u32
                                         8,                          // u64
                                         9.0,                        // f
                                         10.0,                       // d
                                         "foo bar baz",              // str
                                         internal::Enum_Second,      // e
                                         bool_table_offset,          // t
                                         internal::Union_BoolTable,  // u_type
                                         bool_table_offset.Union(),  // u
                                         &s,                         // s
                                         &v_b,                       // v_b
                                         &v_i8,                      // v_i8
                                         &v_i16,                     // v_i16
                                         &v_i32,                     // v_i32
                                         &v_i64,                     // v_i64
                                         &v_u8,                      // v_u8
                                         &v_u16,                     // v_u16
                                         &v_u32,                     // v_u32
                                         &v_u64,                     // v_u64
                                         &v_f,                       // v_f
                                         &v_d,                       // v_d
                                         &v_str,                     // v_str
                                         &v_e,                       // v_e
                                         &v_t,                       // v_t
                                         &v_u_type,                  // v_u_type
                                         &v_u,                       // v_u
                                         &v_s                        // v_s
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
  EXPECT_EQ(new_table->e(), internal::Enum_Second);
  EXPECT_EQ(new_table->u_type(), internal::Union_BoolTable);
  EXPECT_EQ(new_table->u_as_BoolTable()->b(), true);
  ASSERT_THAT(new_table->t(), NotNull());
  EXPECT_EQ(new_table->t()->b(), true);
  ASSERT_THAT(new_table->s(), NotNull());
  EXPECT_EQ(new_table->s()->b(), true);
  EXPECT_EQ(new_table->s()->i8(), 1);
  EXPECT_EQ(new_table->s()->i16(), 2);
  EXPECT_EQ(new_table->s()->i32(), 3);
  EXPECT_EQ(new_table->s()->i64(), 4);
  EXPECT_EQ(new_table->s()->u8(), 5);
  EXPECT_EQ(new_table->s()->u16(), 6);
  EXPECT_EQ(new_table->s()->u32(), 7);
  EXPECT_EQ(new_table->s()->u64(), 8);
  EXPECT_EQ(new_table->s()->f(), 9.0);
  EXPECT_EQ(new_table->s()->d(), 10.0);
  EXPECT_EQ(new_table->s()->e(), internal::Enum_Second);
  EXPECT_EQ(new_table->s()->s().b(), true);
  ASSERT_THAT(new_table->v_b(), NotNull());
  EXPECT_EQ(new_table->v_b()->size(), 2);
  EXPECT_EQ(new_table->v_b()->Get(0), true);
  EXPECT_EQ(new_table->v_b()->Get(1), false);
  ASSERT_THAT(new_table->v_i8(), NotNull());
  EXPECT_EQ(new_table->v_i8()->size(), 3);
  EXPECT_EQ(new_table->v_i8()->Get(0), 1);
  EXPECT_EQ(new_table->v_i8()->Get(1), 2);
  EXPECT_EQ(new_table->v_i8()->Get(2), 3);
  ASSERT_THAT(new_table->v_i16(), NotNull());
  EXPECT_EQ(new_table->v_i16()->size(), 3);
  EXPECT_EQ(new_table->v_i16()->Get(0), 1);
  EXPECT_EQ(new_table->v_i16()->Get(1), 2);
  EXPECT_EQ(new_table->v_i16()->Get(2), 3);
  ASSERT_THAT(new_table->v_i32(), NotNull());
  EXPECT_EQ(new_table->v_i32()->size(), 3);
  EXPECT_EQ(new_table->v_i32()->Get(0), 1);
  EXPECT_EQ(new_table->v_i32()->Get(1), 2);
  EXPECT_EQ(new_table->v_i32()->Get(2), 3);
  ASSERT_THAT(new_table->v_i64(), NotNull());
  EXPECT_EQ(new_table->v_i64()->size(), 3);
  EXPECT_EQ(new_table->v_i64()->Get(0), 1);
  EXPECT_EQ(new_table->v_i64()->Get(1), 2);
  EXPECT_EQ(new_table->v_i64()->Get(2), 3);
  ASSERT_THAT(new_table->v_u8(), NotNull());
  EXPECT_EQ(new_table->v_u8()->size(), 3);
  EXPECT_EQ(new_table->v_u8()->Get(0), 1);
  EXPECT_EQ(new_table->v_u8()->Get(1), 2);
  EXPECT_EQ(new_table->v_u8()->Get(2), 3);
  ASSERT_THAT(new_table->v_u16(), NotNull());
  EXPECT_EQ(new_table->v_u16()->size(), 3);
  EXPECT_EQ(new_table->v_u16()->Get(0), 1);
  EXPECT_EQ(new_table->v_u16()->Get(1), 2);
  EXPECT_EQ(new_table->v_u16()->Get(2), 3);
  ASSERT_THAT(new_table->v_u32(), NotNull());
  EXPECT_EQ(new_table->v_u32()->size(), 3);
  EXPECT_EQ(new_table->v_u32()->Get(0), 1);
  EXPECT_EQ(new_table->v_u32()->Get(1), 2);
  EXPECT_EQ(new_table->v_u32()->Get(2), 3);
  ASSERT_THAT(new_table->v_u64(), NotNull());
  EXPECT_EQ(new_table->v_u64()->size(), 3);
  EXPECT_EQ(new_table->v_u64()->Get(0), 1);
  EXPECT_EQ(new_table->v_u64()->Get(1), 2);
  EXPECT_EQ(new_table->v_u64()->Get(2), 3);
  ASSERT_THAT(new_table->v_f(), NotNull());
  EXPECT_EQ(new_table->v_f()->size(), 3);
  EXPECT_EQ(new_table->v_f()->Get(0), 1);
  EXPECT_EQ(new_table->v_f()->Get(1), 2);
  EXPECT_EQ(new_table->v_f()->Get(2), 3);
  ASSERT_THAT(new_table->v_d(), NotNull());
  EXPECT_EQ(new_table->v_d()->size(), 3);
  EXPECT_EQ(new_table->v_d()->Get(0), 1);
  EXPECT_EQ(new_table->v_d()->Get(1), 2);
  EXPECT_EQ(new_table->v_d()->Get(2), 3);
  EXPECT_EQ(new_table->v_str()->size(), 3);
  EXPECT_EQ(new_table->v_str()->Get(0)->str(), "foo");
  EXPECT_EQ(new_table->v_str()->Get(1)->str(), "bar");
  EXPECT_EQ(new_table->v_str()->Get(2)->str(), "baz");
  ASSERT_THAT(new_table->v_e(), NotNull());
  EXPECT_EQ(new_table->v_e()->size(), 3);
  EXPECT_EQ(new_table->v_e()->Get(0), internal::Enum_First);
  EXPECT_EQ(new_table->v_e()->Get(1), internal::Enum_Second);
  EXPECT_EQ(new_table->v_e()->Get(2), internal::Enum_Third);
  ASSERT_THAT(new_table->v_t(), NotNull());
  EXPECT_EQ(new_table->v_t()->size(), 1);
  ASSERT_THAT(new_table->v_t()->Get(0), NotNull());
  EXPECT_EQ(new_table->v_t()->Get(0)->b(), true);
  ASSERT_THAT(new_table->v_u_type(), NotNull());
  EXPECT_EQ(new_table->v_u_type()->size(), 2);
  EXPECT_EQ(new_table->v_u_type()->Get(0), internal::Union_BoolTable);
  EXPECT_EQ(new_table->v_u_type()->Get(1), internal::Union_StringTable);
  ASSERT_THAT(new_table->v_u(), NotNull());
  EXPECT_EQ(new_table->v_u()->size(), 2);
  auto v_u_0 =
      static_cast<const internal::BoolTable*>(new_table->v_u()->Get(0));
  ASSERT_THAT(v_u_0, NotNull());
  EXPECT_EQ(v_u_0->b(), true);
  auto v_u_1 =
      static_cast<const internal::StringTable*>(new_table->v_u()->Get(1));
  ASSERT_THAT(v_u_1, NotNull());
  ASSERT_THAT(v_u_1->str(), NotNull());
  EXPECT_EQ(v_u_1->str()->str(), "foo bar baz");
  ASSERT_THAT(new_table->v_s(), NotNull());
  EXPECT_EQ(new_table->v_s()->size(), 1);
  ASSERT_THAT(new_table->v_s()->Get(0), NotNull());
  EXPECT_EQ(new_table->v_s()->Get(0)->b(), true);
  EXPECT_EQ(new_table->v_s()->Get(0)->i8(), 1);
  EXPECT_EQ(new_table->v_s()->Get(0)->i16(), 2);
  EXPECT_EQ(new_table->v_s()->Get(0)->i32(), 3);
  EXPECT_EQ(new_table->v_s()->Get(0)->i64(), 4);
  EXPECT_EQ(new_table->v_s()->Get(0)->u8(), 5);
  EXPECT_EQ(new_table->v_s()->Get(0)->u16(), 6);
  EXPECT_EQ(new_table->v_s()->Get(0)->u32(), 7);
  EXPECT_EQ(new_table->v_s()->Get(0)->u64(), 8);
  EXPECT_EQ(new_table->v_s()->Get(0)->f(), 9.0);
  EXPECT_EQ(new_table->v_s()->Get(0)->d(), 10.0);
  EXPECT_EQ(new_table->v_s()->Get(0)->e(), internal::Enum_Second);
  EXPECT_EQ(new_table->v_s()->Get(0)->s().b(), true);
}

TEST(FlatbuffersTableDomainImplTest, InitGeneratesSeeds) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table = CreateDefaultTable(fbb);

  auto domain = Arbitrary<DefaultTable>();
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
                    Eq(val.user_value->str(), table->str()) &&
                    Eq(val.user_value->t(), table->t()) &&
                    Eq(std::make_pair(
                           static_cast<uint8_t>(val.user_value->u_type()),
                           val.user_value->u()),
                       std::make_pair(static_cast<uint8_t>(table->u_type()),
                                      table->u())) &&
                    Eq(val.user_value->s(), table->s()) &&
                    VectorEq(val.user_value->v_b(), table->v_b()) &&
                    VectorEq(val.user_value->v_i8(), table->v_i8()) &&
                    VectorEq(val.user_value->v_i16(), table->v_i16()) &&
                    VectorEq(val.user_value->v_i32(), table->v_i32()) &&
                    VectorEq(val.user_value->v_i64(), table->v_i64()) &&
                    VectorEq(val.user_value->v_u8(), table->v_u8()) &&
                    VectorEq(val.user_value->v_u16(), table->v_u16()) &&
                    VectorEq(val.user_value->v_u32(), table->v_u32()) &&
                    VectorEq(val.user_value->v_u64(), table->v_u64()) &&
                    VectorEq(val.user_value->v_f(), table->v_f()) &&
                    VectorEq(val.user_value->v_d(), table->v_d()) &&
                    VectorEq(val.user_value->v_str(), table->v_str()) &&
                    VectorEq(val.user_value->v_e(), table->v_e()) &&
                    VectorEq(val.user_value->v_t(), table->v_t()) &&
                    VectorUnionEq(val.user_value->v_u_type(),
                                  val.user_value->v_u(), table->v_u_type(),
                                  table->v_u()) &&
                    VectorEq(val.user_value->v_s(), table->v_s()));
          },
          IsTrue())));
}

TEST(FlatbuffersTableDomainImplTest, EventuallyMutatesAllTableFields) {
  absl::flat_hash_map<std::string, bool> mutated_fields{
      {"b", false},       {"i8", false},         {"i16", false},
      {"i32", false},     {"i64", false},        {"u8", false},
      {"u16", false},     {"u32", false},        {"u64", false},
      {"f", false},       {"d", false},          {"str", false},
      {"e", false},       {"t", false},          {"u_type", false},
      {"u", false},       {"s", false},          {"t.v_b", false},
      {"t.v_i8", false},  {"t.v_i16", false},    {"t.v_i32", false},
      {"t.v_i64", false}, {"t.v_u8", false},     {"t.v_u16", false},
      {"t.v_u32", false}, {"t.v_u64", false},    {"t.v_f", false},
      {"t.v_d", false},   {"t.v_e", false},      {"t.v_str", false},
      {"t.v_t", false},   {"t.v_u_type", false}, {"t.v_u", false},
      {"t.v_s", false},
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
    mutated_fields["str"] |= Eq(mut->str(), init->str());
    mutated_fields["e"] |= !Eq(mut->e(), init->e());
    mutated_fields["t"] |= Eq(mut->t(), init->t());
    mutated_fields["u_type"] |= Eq(mut->u_type(), init->u_type());
    mutated_fields["u"] |=
        !Eq(std::make_pair(static_cast<uint8_t>(mut->u_type()), mut->u()),
            std::make_pair(static_cast<uint8_t>(init->u_type()), init->u()));
    mutated_fields["s"] |= !Eq(mut->s(), init->s());
    mutated_fields["t.v_b"] |= !VectorEq(mut->v_b(), init->v_b());
    mutated_fields["t.v_i8"] |= !VectorEq(mut->v_i8(), init->v_i8());
    mutated_fields["t.v_i16"] |= !VectorEq(mut->v_i16(), init->v_i16());
    mutated_fields["t.v_i32"] |= !VectorEq(mut->v_i32(), init->v_i32());
    mutated_fields["t.v_i64"] |= !VectorEq(mut->v_i64(), init->v_i64());
    mutated_fields["t.v_u8"] |= !VectorEq(mut->v_u8(), init->v_u8());
    mutated_fields["t.v_u16"] |= !VectorEq(mut->v_u16(), init->v_u16());
    mutated_fields["t.v_u32"] |= !VectorEq(mut->v_u32(), init->v_u32());
    mutated_fields["t.v_u64"] |= !VectorEq(mut->v_u64(), init->v_u64());
    mutated_fields["t.v_f"] |= !VectorEq(mut->v_f(), init->v_f());
    mutated_fields["t.v_d"] |= !VectorEq(mut->v_d(), init->v_d());
    mutated_fields["t.v_e"] |= !VectorEq(mut->v_e(), init->v_e());
    mutated_fields["t.v_str"] |= !VectorEq(mut->v_str(), init->v_str());
    mutated_fields["t.v_t"] |= !VectorEq(mut->v_str(), init->v_str());
    mutated_fields["t.v_u_type"] |=
        !VectorEq(mut->v_u_type(), init->v_u_type());
    mutated_fields["t.v_u"] |= !VectorUnionEq(mut->v_u_type(), mut->v_u(),
                                              init->v_u_type(), init->v_u());
    mutated_fields["t.v_s"] |= !VectorEq(mut->v_s(), init->v_s());

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
  auto bool_table_offset = internal::CreateBoolTable(fbb, true);
  DefaultStruct s;
  std::vector<uint8_t> v_b{true, false};
  std::vector<int8_t> v_i8{};
  std::vector<int16_t> v_i16{};
  std::vector<int32_t> v_i32{};
  std::vector<int64_t> v_i64{};
  std::vector<uint8_t> v_u8{};
  std::vector<uint16_t> v_u16{};
  std::vector<uint32_t> v_u32{};
  std::vector<uint64_t> v_u64{};
  std::vector<float> v_f{};
  std::vector<double> v_d{};
  std::vector<flatbuffers::Offset<flatbuffers::String>> v_str{
      fbb.CreateString(""), fbb.CreateString(""), fbb.CreateString("")};
  std::vector<std::underlying_type_t<Enum>> v_e{};
  std::vector<flatbuffers::Offset<BoolTable>> v_t{};
  std::vector<std::underlying_type_t<internal::Union>> v_u_type{};
  std::vector<flatbuffers::Offset<>> v_u{};
  std::vector<DefaultStruct> v_s{};
  auto table_offset =
      internal::CreateOptionalTableDirect(fbb,
                                          true,                       // b
                                          1,                          // i8
                                          2,                          // i16
                                          3,                          // i32
                                          4,                          // i64
                                          5,                          // u8
                                          6,                          // u16
                                          7,                          // u32
                                          8,                          // u64
                                          9.0,                        // f
                                          10.0,                       // d
                                          "foo bar baz",              // str
                                          internal::Enum_Second,      // e
                                          bool_table_offset,          // t
                                          internal::Union_BoolTable,  // u_type
                                          bool_table_offset.Union(),  // u
                                          &s,
                                          &v_b,       // v_b
                                          &v_i8,      // v_i8
                                          &v_i16,     // v_i16
                                          &v_i32,     // v_i32
                                          &v_i64,     // v_i64
                                          &v_u8,      // v_u8
                                          &v_u16,     // v_u16
                                          &v_u32,     // v_u32
                                          &v_u64,     // v_u64
                                          &v_f,       // v_f
                                          &v_d,       // v_d
                                          &v_str,     // v_str
                                          &v_e,       // v_e
                                          &v_t,       // v_t
                                          &v_u_type,  // v_u_type
                                          &v_u,       // v_u
                                          &v_s        // v_s
      );
  fbb.Finish(table_offset);
  auto table = flatbuffers::GetRoot<OptionalTable>(fbb.GetBufferPointer());

  auto domain = Arbitrary<OptionalTable>();
  Value val(domain, table);
  absl::BitGen bitgen;

  absl::flat_hash_map<std::string, bool> null_fields{
      {"b", false},       {"i8", false},         {"i16", false},
      {"i32", false},     {"i64", false},        {"u8", false},
      {"u16", false},     {"u32", false},        {"u64", false},
      {"f", false},       {"d", false},          {"str", false},
      {"e", false},       {"t", false},          {"u_type", false},
      {"u", false},       {"s", false},          {"t.v_b", false},
      {"t.v_i8", false},  {"t.v_i16", false},    {"t.v_i32", false},
      {"t.v_i64", false}, {"t.v_u8", false},     {"t.v_u16", false},
      {"t.v_u32", false}, {"t.v_u64", false},    {"t.v_f", false},
      {"t.v_d", false},   {"t.v_e", false},      {"t.v_str", false},
      {"t.v_t", false},   {"t.v_u_type", false}, {"t.v_u", false},
      {"t.v_s", false},
  };

  for (size_t i = 0; i < 1'000'000; ++i) {
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
    null_fields["t"] |= v->t() == nullptr;
    null_fields["u_type"] |= v->u_type() == internal::Union_NONE;
    null_fields["u"] |= v->u() == nullptr;
    null_fields["s"] |= v->s() == nullptr;
    null_fields["t.v_b"] |= v->v_b() == nullptr;
    null_fields["t.v_i8"] |= v->v_i8() == nullptr;
    null_fields["t.v_i16"] |= v->v_i16() == nullptr;
    null_fields["t.v_i32"] |= v->v_i32() == nullptr;
    null_fields["t.v_i64"] |= v->v_i64() == nullptr;
    null_fields["t.v_u8"] |= v->v_u8() == nullptr;
    null_fields["t.v_u16"] |= v->v_u16() == nullptr;
    null_fields["t.v_u32"] |= v->v_u32() == nullptr;
    null_fields["t.v_u64"] |= v->v_u64() == nullptr;
    null_fields["t.v_f"] |= v->v_f() == nullptr;
    null_fields["t.v_d"] |= v->v_d() == nullptr;
    null_fields["t.v_e"] |= v->v_e() == nullptr;
    null_fields["t.v_str"] |= v->v_str() == nullptr;
    null_fields["t.v_t"] |= v->v_t() == nullptr;
    null_fields["t.v_u_type"] |= v->v_u_type() == nullptr;
    null_fields["t.v_u"] |= v->v_u() == nullptr;
    null_fields["t.v_s"] |= v->v_s() == nullptr;

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
  auto bool_table_offset = internal::CreateBoolTable(fbb, true);
  auto string_table_offset =
      internal::CreateStringTableDirect(fbb, "foo bar baz");
  DefaultStruct s{
      true,                   // b
      1,                      // i8
      2,                      // i16
      3,                      // i32
      4,                      // i64
      5,                      // u8
      6,                      // u16
      7,                      // u32
      8,                      // u64
      9,                      // f
      10.0,                   // d
      internal::Enum_Second,  // e
      BoolStruct{true}        // s
  };
  std::vector<uint8_t> v_b{true, false};
  std::vector<int8_t> v_i8{1, 2, 3};
  std::vector<int16_t> v_i16{1, 2, 3};
  std::vector<int32_t> v_i32{1, 2, 3};
  std::vector<int64_t> v_i64{1, 2, 3};
  std::vector<uint8_t> v_u8{1, 2, 3};
  std::vector<uint16_t> v_u16{1, 2, 3};
  std::vector<uint32_t> v_u32{1, 2, 3};
  std::vector<uint64_t> v_u64{1, 2, 3};
  std::vector<float> v_f{1.0, 2.0, 3.0};
  std::vector<double> v_d{1.0, 2.0, 3.0};
  std::vector<flatbuffers::Offset<flatbuffers::String>> v_str{
      fbb.CreateString("foo"), fbb.CreateString("bar"),
      fbb.CreateString("baz")};
  std::vector<std::underlying_type_t<Enum>> v_e{
      internal::Enum_First,
      internal::Enum_Second,
      internal::Enum_Third,
  };
  std::vector<flatbuffers::Offset<BoolTable>> v_t{bool_table_offset};
  std::vector<std::underlying_type_t<internal::Union>> v_u_type{
      internal::Union_BoolTable, internal::Union_StringTable};
  std::vector<flatbuffers::Offset<>> v_u{bool_table_offset.Union(),
                                         string_table_offset.Union()};
  std::vector<DefaultStruct> v_s{s};
  auto table_offset =
      internal::CreateRequiredTableDirect(fbb,
                                          "foo bar baz",              // str
                                          bool_table_offset,          // t
                                          internal::Union_BoolTable,  // u_type
                                          bool_table_offset.Union(),  // u
                                          &s,                         // s
                                          &v_b,                       // v_b
                                          &v_i8,                      // v_i8
                                          &v_i16,                     // v_i16
                                          &v_i32,                     // v_i32
                                          &v_i64,                     // v_i64
                                          &v_u8,                      // v_u8
                                          &v_u16,                     // v_u16
                                          &v_u32,                     // v_u32
                                          &v_u64,                     // v_u64
                                          &v_f,                       // v_f
                                          &v_d,                       // v_d
                                          &v_str,                     // v_str
                                          &v_e,                       // v_e
                                          &v_t,                       // v_t
                                          &v_u_type,  // v_u_type
                                          &v_u,       // v_u
                                          &v_s        // v_s
      );
  fbb.Finish(table_offset);
  auto table = flatbuffers::GetRoot<RequiredTable>(fbb.GetBufferPointer());

  auto domain = Arbitrary<RequiredTable>();
  Value val(domain, table);
  absl::BitGen bitgen;

  absl::flat_hash_map<std::string, bool> set_fields{
      {"str", false},     {"t", false},          {"u_type", false},
      {"u", false},       {"s", false},          {"t.v_b", false},
      {"t.v_i8", false},  {"t.v_i16", false},    {"t.v_i32", false},
      {"t.v_i64", false}, {"t.v_u8", false},     {"t.v_u16", false},
      {"t.v_u32", false}, {"t.v_u64", false},    {"t.v_f", false},
      {"t.v_d", false},   {"t.v_e", false},      {"t.v_str", false},
      {"t.v_t", false},   {"t.v_u_type", false}, {"t.v_u", false},
      {"t.v_s", false},
  };

  for (size_t i = 0; i < 10'000; ++i) {
    val.Mutate(domain, bitgen, {}, true);
    const auto& v = val.user_value;

    set_fields["str"] |= v->str() != nullptr;
    set_fields["t"] |= v->t() != nullptr;
    set_fields["u_type"] |= v->u_type() != internal::Union_NONE;
    set_fields["u"] |= v->u() != nullptr;
    set_fields["s"] |= v->s() != nullptr;
    set_fields["t.v_b"] |= v->v_b() != nullptr;
    set_fields["t.v_i8"] |= v->v_i8() != nullptr;
    set_fields["t.v_i16"] |= v->v_i16() != nullptr;
    set_fields["t.v_i32"] |= v->v_i32() != nullptr;
    set_fields["t.v_i64"] |= v->v_i64() != nullptr;
    set_fields["t.v_u8"] |= v->v_u8() != nullptr;
    set_fields["t.v_u16"] |= v->v_u16() != nullptr;
    set_fields["t.v_u32"] |= v->v_u32() != nullptr;
    set_fields["t.v_u64"] |= v->v_u64() != nullptr;
    set_fields["t.v_f"] |= v->v_f() != nullptr;
    set_fields["t.v_d"] |= v->v_d() != nullptr;
    set_fields["t.v_e"] |= v->v_e() != nullptr;
    set_fields["t.v_str"] |= v->v_str() != nullptr;
    set_fields["t.v_t"] |= v->v_t() != nullptr;
    set_fields["t.v_u_type"] |= v->v_u_type() != nullptr;
    set_fields["t.v_u"] |= v->v_u() != nullptr;
    set_fields["t.v_s"] |= v->v_s() != nullptr;

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

TEST(FlatbuffersTableDomainImplTest, CountNumberOfFieldsWithNull) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table_offset =
      internal::CreateDefaultTableDirect(fbb,
                                         true,                  // b
                                         1,                     // i8
                                         2,                     // i16
                                         3,                     // i32
                                         4,                     // i64
                                         5,                     // u8
                                         6,                     // u16
                                         7,                     // u32
                                         8,                     // u64
                                         9.0,                   // f
                                         10.0,                  // d
                                         "foo bar baz",         // str
                                         internal::Enum_Second  // e
      );
  fbb.Finish(table_offset);
  auto table = flatbuffers::GetRoot<DefaultTable>(fbb.GetBufferPointer());

  auto domain = Arbitrary<DefaultTable>();
  auto corpus = domain.FromValue(table);
  ASSERT_TRUE(corpus.has_value());
  EXPECT_EQ(domain.CountNumberOfFields(corpus.value()), 32);
}

TEST(FlatbuffersUnionDomainImpl, ParseCorpusRejectsInvalidValues) {
  auto domain = Arbitrary<UnionTable>();
  {
    flatbuffers::FlatBufferBuilder fbb;
    internal::CreateUnionTable(fbb, internal::Union_BoolTable, 0);
    fbb.Finish(internal::CreateUnionTable(fbb, internal::Union_BoolTable, 0));
    auto table = flatbuffers::GetRoot<UnionTable>(fbb.GetBufferPointer());
    flatbuffers::Verifier verifier(fbb.GetBufferPointer(), fbb.GetSize());
    ASSERT_TRUE(verifier.VerifyBuffer<UnionTable>());

    auto corpus = domain.FromValue(table);
    ASSERT_TRUE(corpus.has_value());
    EXPECT_FALSE(domain.ValidateCorpusValue(corpus.value()).ok());
  }
  {
    internal::IRObject ir_object;
    auto& subs = ir_object.MutableSubs();
    subs.reserve(2);

    auto& u_obj = subs.emplace_back();
    auto& u_subs = u_obj.MutableSubs();
    u_subs.reserve(2);
    u_subs.emplace_back(1);                     // id
    auto& u_opt_value = u_subs.emplace_back();  // value
    auto& u_opt_value_subs = u_opt_value.MutableSubs();
    u_opt_value_subs.reserve(2);
    u_opt_value_subs.emplace_back(1);  // has value
    auto& u_inner_value = u_opt_value_subs.emplace_back();

    u_inner_value.MutableSubs().reserve(2);
    u_inner_value.MutableSubs().emplace_back(-1);  // type (invalid)
    u_inner_value.MutableSubs().emplace_back();    // value

    auto corpus = domain.ParseCorpus(ir_object);
    ASSERT_FALSE(corpus.has_value());
  }
  {
    internal::IRObject ir_object;
    auto& subs = ir_object.MutableSubs();
    subs.reserve(2);

    auto& u_obj = subs.emplace_back();
    auto& u_subs = u_obj.MutableSubs();
    u_subs.reserve(2);
    u_subs.emplace_back(1);                     // id
    auto& u_opt_value = u_subs.emplace_back();  // value
    auto& u_opt_value_subs = u_opt_value.MutableSubs();
    u_opt_value_subs.reserve(2);
    u_opt_value_subs.emplace_back(1);  // has value
    auto& u_inner_value = u_opt_value_subs.emplace_back();

    u_inner_value.MutableSubs().reserve(2);
    u_inner_value.MutableSubs().emplace_back(
        internal::Union_BoolTable);                                 // type
    auto& bool_table = u_inner_value.MutableSubs().emplace_back();  // value
    auto& bool_table_subs = bool_table.MutableSubs();
    bool_table_subs.reserve(2);
    bool_table_subs.emplace_back(200);  // id (invalid)
    u_subs.emplace_back();              // value

    auto corpus = domain.ParseCorpus(ir_object);
    ASSERT_FALSE(corpus.has_value());
  }
}

}  // namespace
}  // namespace fuzztest
