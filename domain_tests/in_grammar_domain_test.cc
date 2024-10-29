// Copyright 2022 Google LLC
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

// Tests of domain `InJsonGrammar`, the one provided example of an InGrammar
// domain.

#include <string>

#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/random.h"
#include "./fuzztest/domain.h"  // IWYU pragma: keep
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/grammars/json_grammar.h"
#include "./fuzztest/internal/serialization.h"
#include "nlohmann/json.hpp"

namespace fuzztest {
namespace {

TEST(InJsonGrammar, InitGeneratesDifferentValidJson) {
  absl::BitGen bitgen;
  auto domain = InJsonGrammar();
  absl::flat_hash_set<std::string> valid_jsons;

  while (valid_jsons.size() < 1000) {
    Value val(domain, bitgen);
    nlohmann::json parsed_json = nlohmann::json::parse(
        val.user_value.begin(), val.user_value.end(), nullptr, false);
    EXPECT_FALSE(parsed_json.is_discarded()) << val;
    valid_jsons.insert(parsed_json.dump());
  }
}

TEST(InJsonGrammar, InitGeneratesShortJson) {
  absl::BitGen bitgen;
  auto domain = InJsonGrammar();

  size_t total_ast_node_num = 0;
  const size_t total_generation_num = 10000;
  for (size_t i = 0; i < total_generation_num; ++i) {
    Value val(domain, bitgen);
    total_ast_node_num += val.corpus_value.NodeCount();
  }

  // The AST generation tries to generate small ASTs. For example, it will only
  // generate one or zero element for a rule `list: element*`. For the current
  // json grammar, the average size (the number of ast nodes) of an ast is 7.
  // TODO(changochen): Say more about the AST size/depth/shape.
  const size_t average_ast_size = total_ast_node_num / total_generation_num;
  EXPECT_NEAR(average_ast_size, 10, 1);
}

TEST(InJsonGrammar, MutateGeneratesValidValues) {
  absl::BitGen bitgen;
  auto domain = InJsonGrammar();
  absl::flat_hash_set<std::string> valid_jsons;
  Value ast(domain, bitgen);

  while (valid_jsons.size() < 5000) {
    ast.Mutate(domain, bitgen, {}, false);
    nlohmann::json parsed_json = nlohmann::json::parse(
        ast.user_value.begin(), ast.user_value.end(), nullptr, false);
    EXPECT_FALSE(parsed_json.is_discarded());
    valid_jsons.insert(parsed_json.dump());
  }
}

TEST(InJsonGrammar, MutateGeneratesDifferentValuesWithHighProb) {
  absl::BitGen bitgen;
  auto domain = InJsonGrammar();
  absl::flat_hash_set<std::string> valid_jsons;
  int num_real_mutation = 0, num_total_mutation = 0;
  Value ast(domain, bitgen);
  nlohmann::json previous_val = nlohmann::json::parse(
      ast.user_value.begin(), ast.user_value.end(), nullptr, false);

  while (valid_jsons.size() < 5000) {
    ++num_total_mutation;
    ast.Mutate(domain, bitgen, {}, false);
    nlohmann::json parsed_json = nlohmann::json::parse(
        ast.user_value.begin(), ast.user_value.end(), nullptr, false);
    valid_jsons.insert(parsed_json.dump());

    // There might be chances that the mutated AST is the same if because
    // mutating regexp doesn't guarantee changes. Otherwise, it guarantees real
    // mutation.
    if (parsed_json != previous_val) ++num_real_mutation;
    previous_val = parsed_json;
  }
  const double probability_of_real_mutation =
      static_cast<double>(num_real_mutation) / num_total_mutation;
  EXPECT_NEAR(probability_of_real_mutation, 0.99, 0.015);
}

TEST(InJsonGrammar, ShrinkModeReducesInputSize) {
  absl::BitGen bitgen;
  auto domain = InJsonGrammar();
  int num_of_successful_shrink = 0;
  int expected_num_of_successful_shrink = 0;
  for (int i = 0; i < 100; ++i) {
    Value val(domain, bitgen);
    size_t original_size = val.corpus_value.NodeCount();
    // If the generated input is big, we expect it to be shrinkable.
    if (original_size > 20) ++expected_num_of_successful_shrink;

    for (int j = 0; j < 10; ++j) {
      val.Mutate(domain, bitgen, {}, true);
      EXPECT_TRUE(val.corpus_value.NodeCount() <= original_size);
    }
    if (original_size > val.corpus_value.NodeCount()) {
      ++num_of_successful_shrink;
    }
  }
  EXPECT_GE(num_of_successful_shrink, expected_num_of_successful_shrink);
}

TEST(InTestGrammar, InGrammarCorpusSerializesCorpusAndParsesCorpusCorrectly) {
  absl::BitGen bitgen;
  auto domain = InJsonGrammar();
  for (int i = 0; i < 1000; ++i) {
    Value val(domain, bitgen);
    std::cout << domain.GetValue(val.corpus_value) << std::endl;
    auto ir_object = domain.SerializeCorpus(val.corpus_value);
    auto ast = domain.ParseCorpus(ir_object);
    ASSERT_TRUE(ast.has_value());
    EXPECT_EQ(domain.GetValue(*ast), val.user_value);
  }
}

}  // namespace
}  // namespace fuzztest
