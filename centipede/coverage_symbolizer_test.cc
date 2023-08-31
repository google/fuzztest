// Copyright 2023 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./centipede/coverage_symbolizer.h"

#include <stddef.h>

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "./centipede/feature.h"

namespace centipede {
namespace {

constexpr size_t kUnusedDomainId = 13;

TEST(DomainSymbolizerTest, InitializeByPopulatingSymbolTable) {
  DomainSymbolizer symbolizer(kUnusedDomainId);
  ASSERT_OK_AND_ASSIGN(auto symbols,
                       symbolizer.InitializeByPopulatingSymbolTable());
  symbols->AddEntry("func_a", "file_line_col:1");
  symbols->AddEntry("func_b", "file_line_col:2");
  symbols->AddEntry("func_c", "file_line_col:3");

  EXPECT_EQ(symbolizer.GetSymbolForIndex(0), "func_a file_line_col:1");
  EXPECT_EQ(symbolizer.GetSymbolForIndex(2), "func_c file_line_col:3");
  EXPECT_EQ(symbolizer.GetSymbolForIndex(1), "func_b file_line_col:2");
}

TEST(DomainSymbolizerTest, InitializeWithSymbolizationFunction) {
  DomainSymbolizer symbolizer(kUnusedDomainId);
  ASSERT_OK(symbolizer.InitializeWithSymbolizationFunction(
      [](size_t idx) { return absl::StrCat(idx, "_llama"); }));

  EXPECT_EQ(symbolizer.GetSymbolForIndex(0), "0_llama");
  EXPECT_EQ(symbolizer.GetSymbolForIndex(2), "2_llama");
  EXPECT_EQ(symbolizer.GetSymbolForIndex(1), "1_llama");
}

TEST(DomainSymbolizerTest, CannotDoubleInitialize) {
  DomainSymbolizer symbolizer1(kUnusedDomainId);
  ASSERT_OK(symbolizer1.InitializeByPopulatingSymbolTable());
  EXPECT_THAT(
      symbolizer1.InitializeWithSymbolizationFunction(
          [](size_t idx) { return "never_used"; }),
      ::testing::status::StatusIs(absl::StatusCode::kFailedPrecondition));

  DomainSymbolizer symbolizer2(kUnusedDomainId);
  ASSERT_OK(symbolizer2.InitializeWithSymbolizationFunction(
      [](size_t idx) { return "never_used"; }));
  EXPECT_THAT(
      symbolizer2.InitializeByPopulatingSymbolTable(),
      ::testing::status::StatusIs(absl::StatusCode::kFailedPrecondition));

  DomainSymbolizer symbolizer3(kUnusedDomainId);
  ASSERT_OK(symbolizer3.InitializeByPopulatingSymbolTable());
  EXPECT_THAT(
      symbolizer3.InitializeByPopulatingSymbolTable(),
      ::testing::status::StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST(DomainSymbolizerTest, UnknownSymbolIfUninitialized) {
  DomainSymbolizer symbolizer(/*domain_id=*/12);
  std::string expected_symbol = "unknown symbol: domain_id=12, idx=10006";
  EXPECT_EQ(symbolizer.GetSymbolForIndex(10006), expected_symbol);
}

TEST(CoverageSymbolizerTest, GetSymbolizerForDomain) {
  CoverageSymbolizer symbolizers;
  ASSERT_OK_AND_ASSIGN(auto pc_symbolizer, symbolizers.GetSymbolizerForDomain(
                                               feature_domains::kPCs));
  ASSERT_OK_AND_ASSIGN(
      auto bounded_path_symbolizer,
      symbolizers.GetSymbolizerForDomain(feature_domains::kBoundedPath));
  EXPECT_NE(pc_symbolizer, bounded_path_symbolizer);

  ASSERT_OK_AND_ASSIGN(
      auto same_pc_symbolizer,
      symbolizers.GetSymbolizerForDomain(feature_domains::kPCs));
  EXPECT_EQ(pc_symbolizer, same_pc_symbolizer);
}

TEST(CoverageSymbolizerTest, CannotGetSymbolizerForInvalidDomain) {
  CoverageSymbolizer symbolizers;
  EXPECT_THAT(symbolizers.GetSymbolizerForDomain(feature_domains::kLastDomain),
              ::testing::status::StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(symbolizers.GetSymbolizerForDomain(feature_domains::Domain(777)),
              ::testing::status::StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CoverageSymbolizerTest, UnknownSymbolForUninitializedDomains) {
  CoverageSymbolizer symbolizers;
  feature_t feature_pc = feature_domains::kPCs.ConvertToMe(7);
  std::string expected_pc_symbol = "unknown symbol: domain_id=1, idx=7";
  EXPECT_EQ(symbolizers.GetSymbolForFeature(feature_pc), expected_pc_symbol);

  feature_t feature_8bit = feature_domains::k8bitCounters.ConvertToMe(2);
  std::string expected_8bit_symbol = "unknown symbol: domain_id=2, idx=2";
  EXPECT_EQ(symbolizers.GetSymbolForFeature(feature_8bit),
            expected_8bit_symbol);
}

TEST(CoverageSymbolizerTest, GetSymbolForFeature) {
  CoverageSymbolizer symbolizers;
  ASSERT_OK_AND_ASSIGN(auto pc_symbolizer, symbolizers.GetSymbolizerForDomain(
                                               feature_domains::kPCs));
  ASSERT_OK(pc_symbolizer->InitializeWithSymbolizationFunction(
      [](size_t idx) { return absl::StrCat("pc_", idx); }));
  ASSERT_OK_AND_ASSIGN(
      auto bounded_path_symbolizer,
      symbolizers.GetSymbolizerForDomain(feature_domains::kBoundedPath));
  ASSERT_OK(bounded_path_symbolizer->InitializeWithSymbolizationFunction(
      [](size_t idx) { return absl::StrCat("bounded_path_", idx); }));

  feature_t feature_pc = feature_domains::kPCs.ConvertToMe(7);
  EXPECT_EQ(symbolizers.GetSymbolForFeature(feature_pc), "pc_7");

  feature_t feature_bounded_path = feature_domains::kBoundedPath.ConvertToMe(7);
  EXPECT_EQ(symbolizers.GetSymbolForFeature(feature_bounded_path),
            "bounded_path_7");
}

}  // namespace
}  // namespace centipede
