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

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "flatbuffers/base.h"
#include "flatbuffers/buffer.h"
#include "flatbuffers/flatbuffer_builder.h"
#include "flatbuffers/reflection_generated.h"
#include "flatbuffers/string.h"
#include "flatbuffers/vector.h"
#include "./fuzztest/domain.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/flatbuffers.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/test_flatbuffers_64bits_generated.h"
#include "./fuzztest/internal/test_flatbuffers_generated.h"

namespace fuzztest {
namespace {

using ::fuzztest::internal::BoolTable;
using ::fuzztest::internal::ByteEnum;
using ::fuzztest::internal::DefaultTable;
using ::fuzztest::internal::DefaultTable64;
using ::fuzztest::internal::IntEnum;
using ::fuzztest::internal::LongEnum;
using ::fuzztest::internal::OptionalTable;
using ::fuzztest::internal::RecursiveTable;
using ::fuzztest::internal::RequiredTable;
using ::fuzztest::internal::ShortEnum;
using ::fuzztest::internal::UByteEnum;
using ::fuzztest::internal::UIntEnum;
using ::fuzztest::internal::ULongEnum;
using ::fuzztest::internal::UnsupportedTypesTable;
using ::fuzztest::internal::UShortEnum;
using ::testing::_;
using ::testing::AllOf;
using ::testing::Each;
using ::testing::HasSubstr;
using ::testing::IsFalse;
using ::testing::IsNull;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::Pair;
using ::testing::ResultOf;

template <typename T>
inline bool Eq(const T& lhs, const T& rhs) {
  return rhs == lhs;
}

template <typename T>
inline bool Eq(const T* lhs, const T* rhs) {
  if (lhs == nullptr && rhs == nullptr) return true;
  if (lhs == nullptr || rhs == nullptr) return false;
  return Eq(*lhs, *rhs);
}

template <>
inline bool Eq<flatbuffers::String>(const flatbuffers::String& lhs,
                                    const flatbuffers::String& rhs) {
  if (lhs.size() != rhs.size()) return false;
  return memcmp(lhs.data(), rhs.data(), lhs.size()) == 0;
}

template <>
inline bool Eq<BoolTable>(const BoolTable& lhs, const BoolTable& rhs) {
  return lhs.b() == rhs.b();
}

template <typename T>
inline bool VectorEq(const flatbuffers::Vector<T>& lhs,
                     const flatbuffers::Vector<T>& rhs) {
  if (lhs.size() != rhs.size()) return false;
  for (int i = 0; i < lhs.size(); ++i) {
    if (!Eq(lhs.Get(i), rhs.Get(i))) return false;
  }
  return true;
}

template <typename T>
inline bool VectorEq(const flatbuffers::Vector<T>* lhs,
                     const flatbuffers::Vector<T>* rhs) {
  if (lhs == nullptr && rhs == nullptr) return true;
  if (lhs == nullptr || rhs == nullptr) return false;
  return VectorEq(*lhs, *rhs);
}

template <>
inline bool Eq<DefaultTable>(const DefaultTable& lhs, const DefaultTable& rhs) {
  const bool eq_b = lhs.b() == rhs.b();
  const bool eq_i8 = lhs.i8() == rhs.i8();
  const bool eq_i16 = lhs.i16() == rhs.i16();
  const bool eq_i32 = lhs.i32() == rhs.i32();
  const bool eq_i64 = lhs.i64() == rhs.i64();
  const bool eq_u8 = lhs.u8() == rhs.u8();
  const bool eq_u16 = lhs.u16() == rhs.u16();
  const bool eq_u32 = lhs.u32() == rhs.u32();
  const bool eq_u64 = lhs.u64() == rhs.u64();
  const bool eq_f = lhs.f() == rhs.f();
  const bool eq_d = lhs.d() == rhs.d();
  const bool eq_str = Eq(lhs.str(), rhs.str());
  const bool eq_ei8 = lhs.ei8() == rhs.ei8();
  const bool eq_ei16 = lhs.ei16() == rhs.ei16();
  const bool eq_ei32 = lhs.ei32() == rhs.ei32();
  const bool eq_ei64 = lhs.ei64() == rhs.ei64();
  const bool eq_eu8 = lhs.eu8() == rhs.eu8();
  const bool eq_eu16 = lhs.eu16() == rhs.eu16();
  const bool eq_eu32 = lhs.eu32() == rhs.eu32();
  const bool eq_eu64 = lhs.eu64() == rhs.eu64();
  const bool eq_t = Eq(lhs.t(), rhs.t());
  const bool eq_v_b = VectorEq(lhs.v_b(), rhs.v_b());
  const bool eq_v_i8 = VectorEq(lhs.v_i8(), rhs.v_i8());
  const bool eq_v_i16 = VectorEq(lhs.v_i16(), rhs.v_i16());
  const bool eq_v_i32 = VectorEq(lhs.v_i32(), rhs.v_i32());
  const bool eq_v_i64 = VectorEq(lhs.v_i64(), rhs.v_i64());
  const bool eq_v_u8 = VectorEq(lhs.v_u8(), rhs.v_u8());
  const bool eq_v_u16 = VectorEq(lhs.v_u16(), rhs.v_u16());
  const bool eq_v_u32 = VectorEq(lhs.v_u32(), rhs.v_u32());
  const bool eq_v_u64 = VectorEq(lhs.v_u64(), rhs.v_u64());
  const bool eq_v_f = VectorEq(lhs.v_f(), rhs.v_f());
  const bool eq_v_d = VectorEq(lhs.v_d(), rhs.v_d());
  const bool eq_v_str = VectorEq(lhs.v_str(), rhs.v_str());
  const bool eq_v_ei8 = VectorEq(lhs.v_ei8(), rhs.v_ei8());
  const bool eq_v_ei16 = VectorEq(lhs.v_ei16(), rhs.v_ei16());
  const bool eq_v_ei32 = VectorEq(lhs.v_ei32(), rhs.v_ei32());
  const bool eq_v_ei64 = VectorEq(lhs.v_ei64(), rhs.v_ei64());
  const bool eq_v_eu8 = VectorEq(lhs.v_eu8(), rhs.v_eu8());
  const bool eq_v_eu16 = VectorEq(lhs.v_eu16(), rhs.v_eu16());
  const bool eq_v_eu32 = VectorEq(lhs.v_eu32(), rhs.v_eu32());
  const bool eq_v_eu64 = VectorEq(lhs.v_eu64(), rhs.v_eu64());
  const bool eq_v_t = VectorEq(lhs.v_t(), rhs.v_t());
  return eq_b && eq_i8 && eq_i16 && eq_i32 && eq_i64 && eq_u8 && eq_u16 &&
         eq_u32 && eq_u64 && eq_f && eq_d && eq_str && eq_ei8 && eq_ei16 &&
         eq_ei32 && eq_ei64 && eq_eu8 && eq_eu16 && eq_eu32 && eq_eu64 &&
         eq_t && eq_v_b && eq_v_i8 && eq_v_i16 && eq_v_i32 && eq_v_i64 &&
         eq_v_u8 && eq_v_u16 && eq_v_u32 && eq_v_u64 && eq_v_f && eq_v_d &&
         eq_v_str && eq_v_ei8 && eq_v_ei16 && eq_v_ei32 && eq_v_ei64 &&
         eq_v_eu8 && eq_v_eu16 && eq_v_eu32 && eq_v_eu64 && eq_v_t;
}

const internal::DefaultTable* CreateDefaultTable(
    flatbuffers::FlatBufferBuilder& fbb) {
  auto bool_table_offset = internal::CreateBoolTable(fbb, true);
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
  std::vector<std::underlying_type_t<ByteEnum>> v_ei8{
      internal::ByteEnum_First, internal::ByteEnum_Second};
  std::vector<std::underlying_type_t<ShortEnum>> v_ei16{
      internal::ShortEnum_First, internal::ShortEnum_Second};
  std::vector<std::underlying_type_t<IntEnum>> v_ei32{internal::IntEnum_First,
                                                      internal::IntEnum_Second};
  std::vector<std::underlying_type_t<LongEnum>> v_ei64{
      internal::LongEnum_First, internal::LongEnum_Second};
  std::vector<std::underlying_type_t<UByteEnum>> v_eu8{
      internal::UByteEnum_First, internal::UByteEnum_Second};
  std::vector<std::underlying_type_t<UShortEnum>> v_eu16{
      internal::UShortEnum_First, internal::UShortEnum_Second};
  std::vector<std::underlying_type_t<UIntEnum>> v_eu32{
      internal::UIntEnum_First, internal::UIntEnum_Second};
  std::vector<std::underlying_type_t<ULongEnum>> v_eu64{
      internal::ULongEnum_First, internal::ULongEnum_Second};
  std::vector<flatbuffers::Offset<BoolTable>> v_t{bool_table_offset};

  auto table_offset =
      internal::CreateDefaultTableDirect(fbb,
                                         /*b=*/true,
                                         /*i8=*/1,
                                         /*i16=*/2,
                                         /*i32=*/3,
                                         /*i64=*/4,
                                         /*u8=*/5,
                                         /*u16=*/6,
                                         /*u32=*/7,
                                         /*u64=*/8,
                                         /*f=*/9.0,
                                         /*d=*/10.0,
                                         /*str=*/"foo bar baz",
                                         /*ei8=*/internal::ByteEnum_Second,
                                         /*ei16=*/internal::ShortEnum_Second,
                                         /*ei32=*/internal::IntEnum_Second,
                                         /*ei64=*/internal::LongEnum_Second,
                                         /*eu8=*/internal::UByteEnum_Second,
                                         /*eu16=*/internal::UShortEnum_Second,
                                         /*eu32=*/internal::UIntEnum_Second,
                                         /*eu64=*/internal::ULongEnum_Second,
                                         /*t=*/bool_table_offset,
                                         /*v_b=*/&v_b,
                                         /*v_i8=*/&v_i8,
                                         /*v_i16=*/&v_i16,
                                         /*v_i32=*/&v_i32,
                                         /*v_i64=*/&v_i64,
                                         /*v_u8=*/&v_u8,
                                         /*v_u16=*/&v_u16,
                                         /*v_u32=*/&v_u32,
                                         /*v_u64=*/&v_u64,
                                         /*v_f=*/&v_f,
                                         /*v_d=*/&v_d,
                                         /*v_str=*/&v_str,
                                         /*v_ei8=*/&v_ei8,
                                         /*v_ei16=*/&v_ei16,
                                         /*v_ei32=*/&v_ei32,
                                         /*v_ei64=*/&v_ei64,
                                         /*v_eu8=*/&v_eu8,
                                         /*v_eu16=*/&v_eu16,
                                         /*v_eu32=*/&v_eu32,
                                         /*v_eu64=*/&v_eu64,
                                         /*v_t=*/&v_t);
  fbb.Finish(table_offset);
  return flatbuffers::GetRoot<DefaultTable>(fbb.GetBufferPointer());
}

// TODO: b/430818627 - Remove and replace usages with GenerateNonUniqueValues.
template <typename Domain>
std::vector<typename Domain::corpus_type> GenerateNonUniqueCorpusValues(
    Domain domain, int num_seeds = 10, int num_mutations = 100,
    const domain_implementor::MutationMetadata& metadata = {},
    bool only_shrink = false) {
  using CorpusT = typename Domain::corpus_type;
  absl::BitGen bitgen;

  std::vector<CorpusT> seeds;
  seeds.reserve(num_seeds);
  while (seeds.size() < num_seeds) {
    seeds.push_back(domain.Init(bitgen));
  }

  std::vector<CorpusT> values = seeds;

  for (const auto& seed : seeds) {
    CorpusT value = seed;
    std::vector<CorpusT> mutations;
    mutations.reserve(num_mutations);
    while (mutations.size() < num_mutations) {
      domain.Mutate(value, bitgen, metadata, only_shrink);
      mutations.push_back(value);
    }
    values.insert(values.end(), mutations.begin(), mutations.end());
  }

  return values;
};

// TODO: b/430818627 - Remove and replace usages with GenerateInitialValues.
template <typename Domain>
std::vector<typename Domain::corpus_type> GenerateInitialCorpusValues(
    Domain domain, int n) {
  std::vector<typename Domain::corpus_type> values;
  absl::BitGen bitgen;
  values.reserve(n);
  for (int i = 0; i < n; ++i) {
    values.push_back(domain.Init(bitgen));
  }
  return values;
}

TEST(FlatbuffersEnumDomainImplTest, ExcludedValuesAreNotGenerated) {
  const reflection::Schema* schema =
      reflection::GetSchema(DefaultTable::BinarySchema::data());
  const reflection::Enum* enum_def =
      schema->enums()->LookupByKey("fuzztest.internal.ByteEnum");
  auto domain =
      internal::FlatbuffersEnumDomainImpl<uint8_t>(enum_def).WithExcludedValues(
          {internal::ByteEnum_Second});
  EXPECT_THAT(
      GenerateInitialCorpusValues(
          domain, IterationsToHitAll(
                      internal::ByteEnum_MAX - internal::ByteEnum_MIN,
                      1.0 / (internal::ByteEnum_MAX - internal::ByteEnum_MIN))),
      Each(ResultOf(
          [&domain](const auto& corpus) {
            return domain.GetValue(corpus) != internal::ByteEnum_Second;
          },
          IsTrue())));
}

TEST(FlatbuffersEnumDomainImplTest, InvalidEnumValuesAreRejected) {
  const reflection::Schema* schema =
      reflection::GetSchema(DefaultTable::BinarySchema::data());
  const reflection::Enum* enum_def =
      schema->enums()->LookupByKey("fuzztest.internal.ByteEnum");
  auto domain =
      internal::FlatbuffersEnumDomainImpl<uint8_t>(enum_def).WithExcludedValues(
          {internal::ByteEnum_First});
  {
    auto invalid_value =
        static_cast<internal::FlatbuffersEnumDomainImpl<uint8_t>::corpus_type>(
            internal::ByteEnum_MIN - 1);

    EXPECT_THAT(domain.ValidateCorpusValue(invalid_value),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  {
    auto invalid_value =
        static_cast<internal::FlatbuffersEnumDomainImpl<uint8_t>::corpus_type>(
            internal::ByteEnum_MAX + 1);

    EXPECT_THAT(domain.ValidateCorpusValue(invalid_value),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  {
    auto invalid_value =
        static_cast<internal::FlatbuffersEnumDomainImpl<uint8_t>::corpus_type>(
            internal::ByteEnum_First);
    EXPECT_THAT(domain.ValidateCorpusValue(invalid_value),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(FlatbuffersMetaTest, IsFlatbuffersTable) {
  static_assert(internal::is_flatbuffers_table_v<DefaultTable>);
  static_assert(!internal::is_flatbuffers_table_v<int>);
  static_assert(!internal::is_flatbuffers_table_v<std::optional<bool>>);
}

TEST(FlatbuffersTableDomainImplTest, DefaultTableValueRoundTrip) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table = CreateDefaultTable(fbb);

  auto domain = Arbitrary<const DefaultTable*>();
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
  ASSERT_THAT(new_table->str(), NotNull());
  EXPECT_EQ(new_table->str()->str(), "foo bar baz");
  EXPECT_EQ(new_table->ei8(), internal::ByteEnum_Second);
  EXPECT_EQ(new_table->ei16(), internal::ShortEnum_Second);
  EXPECT_EQ(new_table->ei32(), internal::IntEnum_Second);
  EXPECT_EQ(new_table->ei64(), internal::LongEnum_Second);
  EXPECT_EQ(new_table->eu8(), internal::UByteEnum_Second);
  EXPECT_EQ(new_table->eu16(), internal::UShortEnum_Second);
  EXPECT_EQ(new_table->eu32(), internal::UIntEnum_Second);
  EXPECT_EQ(new_table->eu64(), internal::ULongEnum_Second);
  ASSERT_THAT(new_table->t(), NotNull());
  EXPECT_EQ(new_table->t()->b(), true);
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
  ASSERT_THAT(new_table->v_ei8(), NotNull());
  EXPECT_EQ(new_table->v_ei8()->size(), 2);
  EXPECT_EQ(new_table->v_ei8()->Get(0), internal::ByteEnum_First);
  EXPECT_EQ(new_table->v_ei8()->Get(1), internal::ByteEnum_Second);
  ASSERT_THAT(new_table->v_ei16(), NotNull());
  EXPECT_EQ(new_table->v_ei16()->size(), 2);
  EXPECT_EQ(new_table->v_ei16()->Get(0), internal::ShortEnum_First);
  EXPECT_EQ(new_table->v_ei16()->Get(1), internal::ShortEnum_Second);
  ASSERT_THAT(new_table->v_ei32(), NotNull());
  EXPECT_EQ(new_table->v_ei32()->size(), 2);
  EXPECT_EQ(new_table->v_ei32()->Get(0), internal::IntEnum_First);
  EXPECT_EQ(new_table->v_ei32()->Get(1), internal::IntEnum_Second);
  ASSERT_THAT(new_table->v_ei64(), NotNull());
  EXPECT_EQ(new_table->v_ei64()->size(), 2);
  EXPECT_EQ(new_table->v_ei64()->Get(0), internal::LongEnum_First);
  EXPECT_EQ(new_table->v_ei64()->Get(1), internal::LongEnum_Second);
  ASSERT_THAT(new_table->v_eu8(), NotNull());
  EXPECT_EQ(new_table->v_eu8()->size(), 2);
  EXPECT_EQ(new_table->v_eu8()->Get(0), internal::UByteEnum_First);
  EXPECT_EQ(new_table->v_eu8()->Get(1), internal::UByteEnum_Second);
  ASSERT_THAT(new_table->v_eu16(), NotNull());
  EXPECT_EQ(new_table->v_eu16()->size(), 2);
  EXPECT_EQ(new_table->v_eu16()->Get(0), internal::UShortEnum_First);
  EXPECT_EQ(new_table->v_eu16()->Get(1), internal::UShortEnum_Second);
  ASSERT_THAT(new_table->v_eu32(), NotNull());
  EXPECT_EQ(new_table->v_eu32()->size(), 2);
  EXPECT_EQ(new_table->v_eu32()->Get(0), internal::UIntEnum_First);
  EXPECT_EQ(new_table->v_eu32()->Get(1), internal::UIntEnum_Second);
  ASSERT_THAT(new_table->v_t(), NotNull());
  EXPECT_EQ(new_table->v_t()->size(), 1);
  ASSERT_THAT(new_table->v_t()->Get(0), NotNull());
  EXPECT_EQ(new_table->v_t()->Get(0)->b(), true);
}

TEST(FlatbuffersTableDomainImplTest, InitGeneratesSeeds) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table = CreateDefaultTable(fbb);

  auto domain = Arbitrary<const DefaultTable*>().WithSeeds({table});

  EXPECT_THAT(GenerateInitialCorpusValues(domain, IterationsToHitAll(1, 0.5)),
              Contains(ResultOf(
                  [table, &domain](
                      const typename decltype(domain)::corpus_type& corpus) {
                    return Eq(domain.GetValue(corpus), table);
                  },
                  IsTrue())));
}

TEST(FlatbuffersTableDomainImplTest, CanMutateAnyTableField) {
  absl::flat_hash_map<std::string, bool> mutated_fields{
      {"b", false},      {"i8", false},    {"i16", false},    {"i32", false},
      {"i64", false},    {"u8", false},    {"u16", false},    {"u32", false},
      {"u64", false},    {"f", false},     {"d", false},      {"str", false},
      {"ei8", false},    {"ei16", false},  {"ei32", false},   {"ei64", false},
      {"eu8", false},    {"eu16", false},  {"eu32", false},   {"eu64", false},
      {"t", false},      {"v_b", false},   {"v_i8", false},   {"v_i16", false},
      {"v_i32", false},  {"v_i64", false}, {"v_u8", false},   {"v_u16", false},
      {"v_u32", false},  {"v_u64", false}, {"v_f", false},    {"v_d", false},
      {"v_str", false},  {"v_ei8", false}, {"v_ei16", false}, {"v_ei32", false},
      {"v_ei64", false}, {"v_eu8", false}, {"v_eu16", false}, {"v_eu32", false},
      {"v_eu64", false}, {"v_t", false},
  };

  auto domain = Arbitrary<const DefaultTable*>();

  absl::BitGen bitgen;
  for (size_t i = 0; i < IterationsToHitAll(mutated_fields.size(),
                                            1.0 / mutated_fields.size());
       ++i) {
    Value initial_val(domain, bitgen);
    Value val(initial_val);
    val.Mutate(domain, bitgen, {}, false);
    const auto& mut = val.user_value;
    const auto& init = initial_val.user_value;

    mutated_fields["b"] |= mut->b() != init->b();
    mutated_fields["i8"] |= mut->i8() != init->i8();
    mutated_fields["i16"] |= mut->i16() != init->i16();
    mutated_fields["i32"] |= mut->i32() != init->i32();
    mutated_fields["i64"] |= mut->i64() != init->i64();
    mutated_fields["u8"] |= mut->u8() != init->u8();
    mutated_fields["u16"] |= mut->u16() != init->u16();
    mutated_fields["u32"] |= mut->u32() != init->u32();
    mutated_fields["u64"] |= mut->u64() != init->u64();
    mutated_fields["f"] |= mut->f() != init->f();
    mutated_fields["d"] |= mut->d() != init->d();
    mutated_fields["str"] |= !Eq(mut->str(), init->str());
    mutated_fields["ei8"] |= mut->ei8() != init->ei8();
    mutated_fields["ei16"] |= mut->ei16() != init->ei16();
    mutated_fields["ei32"] |= mut->ei32() != init->ei32();
    mutated_fields["ei64"] |= mut->ei64() != init->ei64();
    mutated_fields["eu8"] |= mut->eu8() != init->eu8();
    mutated_fields["eu16"] |= mut->eu16() != init->eu16();
    mutated_fields["eu32"] |= mut->eu32() != init->eu32();
    mutated_fields["eu64"] |= mut->eu64() != init->eu64();
    mutated_fields["t"] |= !Eq(mut->t(), init->t());
    mutated_fields["v_b"] |= !VectorEq(mut->v_b(), init->v_b());
    mutated_fields["v_i8"] |= !VectorEq(mut->v_i8(), init->v_i8());
    mutated_fields["v_i16"] |= !VectorEq(mut->v_i16(), init->v_i16());
    mutated_fields["v_i32"] |= !VectorEq(mut->v_i32(), init->v_i32());
    mutated_fields["v_i64"] |= !VectorEq(mut->v_i64(), init->v_i64());
    mutated_fields["v_u8"] |= !VectorEq(mut->v_u8(), init->v_u8());
    mutated_fields["v_u16"] |= !VectorEq(mut->v_u16(), init->v_u16());
    mutated_fields["v_u32"] |= !VectorEq(mut->v_u32(), init->v_u32());
    mutated_fields["v_u64"] |= !VectorEq(mut->v_u64(), init->v_u64());
    mutated_fields["v_f"] |= !VectorEq(mut->v_f(), init->v_f());
    mutated_fields["v_d"] |= !VectorEq(mut->v_d(), init->v_d());
    mutated_fields["v_str"] |= !VectorEq(mut->v_str(), init->v_str());
    mutated_fields["v_ei8"] |= !VectorEq(mut->v_ei8(), init->v_ei8());
    mutated_fields["v_ei16"] |= !VectorEq(mut->v_ei16(), init->v_ei16());
    mutated_fields["v_ei32"] |= !VectorEq(mut->v_ei32(), init->v_ei32());
    mutated_fields["v_ei64"] |= !VectorEq(mut->v_ei64(), init->v_ei64());
    mutated_fields["v_eu8"] |= !VectorEq(mut->v_eu8(), init->v_eu8());
    mutated_fields["v_eu16"] |= !VectorEq(mut->v_eu16(), init->v_eu16());
    mutated_fields["v_eu32"] |= !VectorEq(mut->v_eu32(), init->v_eu32());
    mutated_fields["v_eu64"] |= !VectorEq(mut->v_eu64(), init->v_eu64());
    mutated_fields["v_t"] |= !VectorEq(mut->v_str(), init->v_str());

    if (std::all_of(mutated_fields.begin(), mutated_fields.end(),
                    [](const auto& p) { return p.second; })) {
      break;
    }
  }

  EXPECT_THAT(mutated_fields, Each(Pair(_, true)));
}

TEST(FlatbuffersTableDomainImplTest, OptionalTableEventuallyBecomeEmpty) {
  flatbuffers::FlatBufferBuilder fbb;
  auto bool_table_offset = internal::CreateBoolTable(fbb, true);
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
  std::vector<std::underlying_type_t<ByteEnum>> v_ei8{};
  std::vector<std::underlying_type_t<ShortEnum>> v_ei16{};
  std::vector<std::underlying_type_t<IntEnum>> v_ei32{};
  std::vector<std::underlying_type_t<LongEnum>> v_ei64{};
  std::vector<std::underlying_type_t<UByteEnum>> v_eu8{};
  std::vector<std::underlying_type_t<UShortEnum>> v_eu16{};
  std::vector<std::underlying_type_t<UIntEnum>> v_eu32{};
  std::vector<std::underlying_type_t<ULongEnum>> v_eu64{};
  std::vector<flatbuffers::Offset<BoolTable>> v_t{};
  auto table_offset =
      internal::CreateOptionalTableDirect(fbb,
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
                                          internal::ByteEnum_Second,    // ei8
                                          internal::ShortEnum_Second,   // ei16
                                          internal::IntEnum_Second,     // ei32
                                          internal::LongEnum_Second,    // ei64
                                          internal::UByteEnum_Second,   // eu8
                                          internal::UShortEnum_Second,  // eu16
                                          internal::UIntEnum_Second,    // eu32
                                          internal::ULongEnum_Second,   // eu64
                                          bool_table_offset,            // t
                                          &v_b,                         // v_b
                                          &v_i8,                        // v_i8
                                          &v_i16,                       // v_i16
                                          &v_i32,                       // v_i32
                                          &v_i64,                       // v_i64
                                          &v_u8,                        // v_u8
                                          &v_u16,                       // v_u16
                                          &v_u32,                       // v_u32
                                          &v_u64,                       // v_u64
                                          &v_f,                         // v_f
                                          &v_d,                         // v_d
                                          &v_str,                       // v_str
                                          &v_ei8,                       // v_ei8
                                          &v_ei16,  // v_ei16
                                          &v_ei32,  // v_ei32
                                          &v_ei64,  // v_ei64
                                          &v_eu8,   // v_eu8
                                          &v_eu16,  // v_eu16
                                          &v_eu32,  // v_eu32
                                          &v_eu64,  // v_eu64
                                          &v_t      // v_t
      );
  fbb.Finish(table_offset);
  auto table = flatbuffers::GetRoot<OptionalTable>(fbb.GetBufferPointer());

  auto domain = Arbitrary<const OptionalTable*>();
  Value val(domain, table);
  absl::BitGen bitgen;

  absl::flat_hash_map<std::string, bool> null_fields{
      {"b", false},      {"i8", false},    {"i16", false},    {"i32", false},
      {"i64", false},    {"u8", false},    {"u16", false},    {"u32", false},
      {"u64", false},    {"f", false},     {"d", false},      {"str", false},
      {"ei8", false},    {"ei16", false},  {"ei32", false},   {"ei64", false},
      {"eu8", false},    {"eu16", false},  {"eu32", false},   {"eu64", false},
      {"t", false},      {"v_b", false},   {"v_i8", false},   {"v_i16", false},
      {"v_i32", false},  {"v_i64", false}, {"v_u8", false},   {"v_u16", false},
      {"v_u32", false},  {"v_u64", false}, {"v_f", false},    {"v_d", false},
      {"v_str", false},  {"v_ei8", false}, {"v_ei16", false}, {"v_ei32", false},
      {"v_ei64", false}, {"v_eu8", false}, {"v_eu16", false}, {"v_eu32", false},
      {"v_eu64", false}, {"v_t", false},
  };

  // Optional fields are mutated to null with probability 1/100.
  const int iterations =
      IterationsToHitAll(null_fields.size(), .01 / null_fields.size());
  for (size_t i = 0; i < iterations; ++i) {
    val.Mutate(domain, bitgen, /*metadata=*/{}, /*only_shrink=*/true);
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
    null_fields["t"] |= v->t() == nullptr;
    null_fields["v_b"] |= v->v_b() == nullptr;
    null_fields["v_i8"] |= v->v_i8() == nullptr;
    null_fields["v_i16"] |= v->v_i16() == nullptr;
    null_fields["v_i32"] |= v->v_i32() == nullptr;
    null_fields["v_i64"] |= v->v_i64() == nullptr;
    null_fields["v_u8"] |= v->v_u8() == nullptr;
    null_fields["v_u16"] |= v->v_u16() == nullptr;
    null_fields["v_u32"] |= v->v_u32() == nullptr;
    null_fields["v_u64"] |= v->v_u64() == nullptr;
    null_fields["v_f"] |= v->v_f() == nullptr;
    null_fields["v_d"] |= v->v_d() == nullptr;
    null_fields["v_str"] |= v->v_str() == nullptr;
    null_fields["v_ei8"] |= v->v_ei8() == nullptr;
    null_fields["v_ei16"] |= v->v_ei16() == nullptr;
    null_fields["v_ei32"] |= v->v_ei32() == nullptr;
    null_fields["v_ei64"] |= v->v_ei64() == nullptr;
    null_fields["v_eu8"] |= v->v_eu8() == nullptr;
    null_fields["v_eu16"] |= v->v_eu16() == nullptr;
    null_fields["v_eu32"] |= v->v_eu32() == nullptr;
    null_fields["v_eu64"] |= v->v_eu64() == nullptr;
    null_fields["v_t"] |= v->v_t() == nullptr;

    if (std::all_of(null_fields.begin(), null_fields.end(),
                    [](const auto& p) { return p.second; })) {
      break;
    }
  }

  EXPECT_THAT(null_fields, Each(Pair(_, true)));
}

TEST(FlatbuffersTableDomainImplTest, RequiredTableFieldsAlwaysSet) {
  auto domain = Arbitrary<const RequiredTable*>();

  EXPECT_THAT(GenerateNonUniqueCorpusValues(
                  domain,
                  /*num_seeds=*/1,
                  /*num_mutations=*/IterationsToHitAll(1, 1.0 / 100), {},
                  /*only_shrink=*/true),
              Each(ResultOf(
                  [&](const typename decltype(domain)::corpus_type& corpus) {
                    auto value = domain.GetValue(corpus);
                    return value->str() == nullptr && value->t() == nullptr;
                  },
                  IsFalse())));
}

TEST(FlatbuffersTableDomainImplTest, Printer) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table = CreateDefaultTable(fbb);
  auto domain = Arbitrary<const DefaultTable*>();
  auto corpus = domain.FromValue(table);
  ASSERT_TRUE(corpus.has_value());

  auto printer = domain.GetPrinter();
  std::string out;
  printer.PrintCorpusValue(*corpus, &out,
                           domain_implementor::PrintMode::kHumanReadable);

  EXPECT_THAT(out,
              AllOf(HasSubstr("b: (true)"),                             // b
                    HasSubstr("i8: (1)"),                               // i8
                    HasSubstr("i16: (2)"),                              // i16
                    HasSubstr("i32: (3)"),                              // i32
                    HasSubstr("i64: (4)"),                              // i64
                    HasSubstr("u8: (5)"),                               // u8
                    HasSubstr("u16: (6)"),                              // u16
                    HasSubstr("u32: (7)"),                              // u32
                    HasSubstr("u64: (8)"),                              // u64
                    HasSubstr("f: (9.f)"),                              // f
                    HasSubstr("d: (10.)"),                              // d
                    HasSubstr("str: (\"foo bar baz\")"),                // str
                    HasSubstr("ei8: (Second)"),                         // ei8
                    HasSubstr("ei16: (Second)"),                        // ei16
                    HasSubstr("ei32: (Second)"),                        // ei32
                    HasSubstr("ei64: (Second)"),                        // ei64
                    HasSubstr("eu8: (Second)"),                         // eu8
                    HasSubstr("eu16: (Second)"),                        // eu16
                    HasSubstr("eu32: (Second)"),                        // eu32
                    HasSubstr("eu64: (Second)"),                        // eu64
                    HasSubstr("t: ({b: (true)})"),                      // t
                    HasSubstr("v_b: ({true, false})"),                  // v_b
                    HasSubstr("v_i8: ({1, 2, 3})"),                     // v_i8
                    HasSubstr("v_i16: ({1, 2, 3})"),                    // v_i16
                    HasSubstr("v_i32: ({1, 2, 3})"),                    // v_i32
                    HasSubstr("v_i64: ({1, 2, 3})"),                    // v_i64
                    HasSubstr("v_u8: ({1, 2, 3})"),                     // v_u8
                    HasSubstr("v_u16: ({1, 2, 3})"),                    // v_u16
                    HasSubstr("v_u32: ({1, 2, 3})"),                    // v_u32
                    HasSubstr("v_u64: ({1, 2, 3})"),                    // v_u64
                    HasSubstr("v_f: ({1.f, 2.f, 3.f})"),                // v_f
                    HasSubstr("v_d: ({1., 2., 3.})"),                   // v_d
                    HasSubstr("v_str: ({\"foo\", \"bar\", \"baz\"})"),  // v_str
                    HasSubstr("v_ei8: ({First, Second})"),              // v_ei8
                    HasSubstr("v_ei16: ({First, Second})"),  // v_ei16
                    HasSubstr("v_ei32: ({First, Second})"),  // v_ei32
                    HasSubstr("v_ei64: ({First, Second})"),  // v_ei64
                    HasSubstr("v_eu8: ({First, Second})"),   // v_eu8
                    HasSubstr("v_eu16: ({First, Second})"),  // v_eu16
                    HasSubstr("v_eu32: ({First, Second})"),  // v_eu32
                    HasSubstr("v_eu64: ({First, Second})"),  // v_eu64
                    HasSubstr("v_t: ({{b: (true)}})")        // v_t
                    ));
}

TEST(FlatbuffersTableDomainImplTest, UnsupportedTypesRemainNull) {
  absl::flat_hash_map<std::string, bool> null_fields{
      {"u", true}, {"s", true}, {"v_u", true}, {"v_s", true}};

  auto domain = Arbitrary<const UnsupportedTypesTable*>();

  absl::BitGen bitgen;
  for (size_t i = 0;
       i < IterationsToHitAll(null_fields.size(), 1.0 / null_fields.size());
       ++i) {
    Value val(domain, bitgen);
    val.Mutate(domain, bitgen, {}, false);
    const auto& mut = val.user_value;

    null_fields["u"] &= mut->u() == nullptr;
    null_fields["s"] &= mut->s() == nullptr;
    null_fields["v_u"] &= mut->v_u() == nullptr;
    null_fields["v_s"] &= mut->v_s() == nullptr;

    if (std::any_of(null_fields.begin(), null_fields.end(),
                    [](const auto& p) { return !p.second; })) {
      break;
    }
  }

  EXPECT_THAT(null_fields, Each(Pair(_, true)));
}

TEST(FlatbuffersTableDomainImplTest, MutateAlwaysChangesValues) {
  auto domain = Arbitrary<const DefaultTable*>();
  const reflection::Schema* schema =
      reflection::GetSchema(DefaultTable::BinarySchema::data());
  const reflection::Object* object =
      schema->objects()->LookupByKey(DefaultTable::GetFullyQualifiedName());

  absl::BitGen bitgen;
  size_t iterations = IterationsToHitAll(object->fields()->size(),
                                         1.0 / object->fields()->size());
  typename decltype(domain)::corpus_type corpus = domain.Init(bitgen);
  for (size_t i = 0; i < iterations; ++i) {
    auto mutated_corpus = corpus;
    domain.Mutate(mutated_corpus, bitgen, {}, false);
    EXPECT_FALSE(Eq(domain.GetValue(mutated_corpus), domain.GetValue(corpus)));
    corpus = mutated_corpus;
  }
}

TEST(FlatbuffersTableDomainImplTest, UnsupportedFieldsCountIsZero) {
  auto domain = Arbitrary<const UnsupportedTypesTable*>();
  auto corpus = domain.Init(absl::BitGen());
  EXPECT_EQ(domain.CountNumberOfFields(corpus), 0);
}

TEST(FlatbuffersTableDomainImplTest, CountNumberOfFieldsWithNull) {
  flatbuffers::FlatBufferBuilder fbb;
  auto table_offset = internal::CreateOptionalTableDirect(fbb);
  fbb.Finish(table_offset);
  auto table = flatbuffers::GetRoot<OptionalTable>(fbb.GetBufferPointer());

  auto domain = Arbitrary<const OptionalTable*>();
  auto corpus = domain.FromValue(table);
  ASSERT_TRUE(corpus.has_value());
  EXPECT_EQ(domain.CountNumberOfFields(corpus.value()), 42);
}

TEST(FlatbuffersTableDomainImplTest, RecursiveTable) {
  flatbuffers::FlatBufferBuilder fbb;
  flatbuffers::Offset<RecursiveTable> root_offset;
  const int kDepth = 10;
  for (int i = 0; i < kDepth; ++i) {
    auto nested_table_offset =
        internal::CreateNestedRecursiveTable(fbb, root_offset);
    root_offset = internal::CreateRecursiveTable(fbb, nested_table_offset);
  }
  fbb.Finish(root_offset);
  auto table = flatbuffers::GetRoot<RecursiveTable>(fbb.GetBufferPointer());

  auto domain = Arbitrary<const RecursiveTable*>();
  auto corpus = domain.FromValue(table);
  ASSERT_TRUE(corpus.has_value());
  ASSERT_OK(domain.ValidateCorpusValue(corpus.value()));
  auto new_table = domain.GetValue(corpus.value());
  for (int i = 0; i < kDepth; ++i) {
    auto nested_table = new_table->t();
    ASSERT_THAT(nested_table, NotNull()) << "Depth: " << i;
    new_table = nested_table->t();
  }
  ASSERT_THAT(new_table, IsNull());
}

TEST(FlatbuffersTableDomainImplTest, DefaultTable64ValueRoundTrip) {
  flatbuffers::FlatBufferBuilder64 fbb;
  auto str_offset = fbb.CreateString<flatbuffers::Offset64>("foo bar baz");
  std::vector<uint8_t> v_u8 = {1, 2, 3};
  auto v_u8_offset = fbb.CreateVector64(v_u8);
  auto table_offset =
      internal::CreateDefaultTable64(fbb, str_offset, v_u8_offset);
  fbb.Finish(table_offset);
  auto table = flatbuffers::GetRoot<DefaultTable64>(fbb.GetBufferPointer());

  auto domain = Arbitrary<const DefaultTable64*>();
  auto corpus = domain.FromValue(table);
  ASSERT_TRUE(corpus.has_value());
  ASSERT_OK(domain.ValidateCorpusValue(*corpus));

  auto ir = domain.SerializeCorpus(corpus.value());

  auto new_corpus = domain.ParseCorpus(ir);
  ASSERT_TRUE(new_corpus.has_value());
  ASSERT_OK(domain.ValidateCorpusValue(*new_corpus));

  auto new_table = domain.GetValue(*new_corpus);
  ASSERT_THAT(new_table, NotNull());
  ASSERT_THAT(new_table->str(), NotNull());
  EXPECT_EQ(new_table->str()->str(), "foo bar baz");
  ASSERT_THAT(new_table->v_u8(), NotNull());
  ASSERT_EQ(new_table->v_u8()->size(), 3);
  EXPECT_EQ(new_table->v_u8()->Get(0), 1);
  EXPECT_EQ(new_table->v_u8()->Get(1), 2);
  EXPECT_EQ(new_table->v_u8()->Get(2), 3);
}

}  // namespace
}  // namespace fuzztest
