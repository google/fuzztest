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

#include "./grammar_codegen/backend.h"

#include <cctype>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "./grammar_codegen/grammar_info.h"
#include "./fuzztest/internal/logging.h"

namespace fuzztest::internal::grammar {

namespace {

void AppendRules(std::vector<GrammarRule>& rules,
                 std::vector<GrammarRule> new_rules) {
  rules.insert(rules.end(), new_rules.begin(), new_rules.end());
}

std::vector<GrammarRule> SimplifyProductionWithFallbackIndex(
    ProductionWithFallbackIndex& productions, absl::string_view symbol_name);

void SwitchBlockToNewNonTerminal(Block& block, std::string symbol_name) {
  block.element.emplace<NonTerminal>(NonTerminal{symbol_name});
}

std::string CreateIRNodeNameForClass(absl::string_view symbol_name) {
  static int counter = 0;
  FUZZTEST_INTERNAL_CHECK(
      symbol_name.size() > 4 &&
          symbol_name.substr(symbol_name.size() - 4) == "Node",
      std::string("Not a valid symbol class name: ") + "  " +
          std::string(symbol_name));
  return absl::StrFormat(
      "%sSubNode%d", symbol_name.substr(0, symbol_name.size() - 4), counter++);
}

// Create a IR node for a vector-like block.
// For example, A: B | C*, we convert it into A: B | N, N: C*. So that A can be
// reprensented with a Variant and N can be represented with a Vector.
std::vector<GrammarRule> SimplifyVectorLikeBlock(
    Block& block, absl::string_view parent_symbol_name) {
  Range saved_range = block.range;
  // Set the range to kNoRange to avoid infinite recursion at
  // `SimplifyProductionWithFallbackIndex`.
  block.range = Range::kNoRange;
  ProductionRule prod_rule{{block}};
  std::string new_symbol_name = CreateIRNodeNameForClass(parent_symbol_name);
  SwitchBlockToNewNonTerminal(block, new_symbol_name);
  GrammarRule new_rule = GrammarRule{
      new_symbol_name, ProductionWithFallbackIndex{0, {std::move(prod_rule)}}};
  std::vector<GrammarRule> new_grammar_rules =
      SimplifyProductionWithFallbackIndex(new_rule.productions,
                                          parent_symbol_name);
  new_rule.productions.production_rules[0].blocks[0].range = saved_range;
  std::vector<GrammarRule> result = {new_rule};
  AppendRules(result, std::move(new_grammar_rules));
  return result;
}

// Create a IR node for a tuple-like production.
// For example, A: B | C D, we convert it into A: B | N, N: C D. So that A can
// be reprensented with a Variant and N can be represented with a Tuple.
std::vector<GrammarRule> SimplifyTupleLikeProduction(
    ProductionRule& production, absl::string_view parent_symbol_name) {
  std::string new_symbol_name = CreateIRNodeNameForClass(parent_symbol_name);
  Block block{Range::kNoRange, NonTerminal{new_symbol_name}};
  GrammarRule result = GrammarRule{
      new_symbol_name, ProductionWithFallbackIndex{0, {production}}};
  production = {{block}};
  std::vector<GrammarRule> result_vec = {result};
  AppendRules(result_vec, SimplifyProductionWithFallbackIndex(
                              result.productions, parent_symbol_name));
  return result_vec;
}

// Create a IR node for a variant-like block.
// For example, A: B | (C | D), we convert it into A: B | N, N: C | D. So that
// A can be reprensented with a Variant and N can be represented with a Variant.
//
// Note: Although such a definition seems meaningless, but it is allowed by
// Antlr4.
std::vector<GrammarRule> SimplifyVariantLikeBlock(
    Block& block, absl::string_view parent_symbol_name) {
  ProductionWithFallbackIndex inner =
      std::get<ProductionWithFallbackIndex>(block.element);
  std::string new_symbol_name = CreateIRNodeNameForClass(parent_symbol_name);
  SwitchBlockToNewNonTerminal(block, new_symbol_name);
  auto new_grammar_rules =
      SimplifyProductionWithFallbackIndex(inner, parent_symbol_name);
  new_grammar_rules.emplace_back(GrammarRule{new_symbol_name, inner});
  return new_grammar_rules;
}

std::vector<GrammarRule> SimplifyProductionWithFallbackIndex(
    ProductionWithFallbackIndex& productions, absl::string_view symbol_name) {
  std::vector<GrammarRule> intermediate_grammar_rules;
  for (ProductionRule& production : productions.production_rules) {
    for (Block& block : production.blocks) {
      if (block.range != Range::kNoRange) {
        AppendRules(intermediate_grammar_rules,
                    SimplifyVectorLikeBlock(block, symbol_name));
      }
      if (block.element.index() == BlockType::kSubProductions) {
        AppendRules(intermediate_grammar_rules,
                    SimplifyVariantLikeBlock(block, symbol_name));
      }
    }
    if (productions.production_rules.size() > 1 &&
        production.blocks.size() > 1) {
      AppendRules(intermediate_grammar_rules,
                  SimplifyTupleLikeProduction(production, symbol_name));
    }
  }
  return intermediate_grammar_rules;
}

std::string WrapChildTypeWithRangedVector(absl::string_view parent_type,
                                          absl::string_view child_type,
                                          const Range range) {
  switch (range) {
    case Range::kNoRange:
      return std::string(child_type);
    case Range::kUnlimited:
      return absl::StrFormat("Vector<k%s, %s>", parent_type, child_type);
    case Range::kNonEmpty:
      return absl::StrFormat("NonEmptyVector<k%s, %s>", parent_type,
                             child_type);
    case Range::kOptional:
      return absl::StrFormat("Optional<k%s, %s>", parent_type, child_type);
  }
}

bool HasEOF(const ProductionWithFallbackIndex& production) {
  for (const ProductionRule& production_rule : production.production_rules) {
    for (const Block& block : production_rule.blocks) {
      const auto& element = block.element;
      if (element.index() == BlockType::kNonTerminal) {
        if (std::get<NonTerminal>(element).name == "EOF") {
          return true;
        }
      } else if (element.index() == BlockType::kSubProductions) {
        if (HasEOF(std::get<ProductionWithFallbackIndex>(element))) {
          return true;
        }
      }
    }
  }
  return false;
}

bool HasEOF(const Grammar& grammar) {
  for (const GrammarRule& rule : grammar.rules) {
    if (HasEOF(rule.productions)) {
      return true;
    }
  }
  return false;
}
}  // namespace

void CodeGenerator::Preprocess(Grammar& grammar) {
  std::vector<GrammarRule> new_grammar_rules;
  for (GrammarRule& rule : grammar.rules) {
    auto new_ir_rules = SimplifyProductionWithFallbackIndex(
        rule.productions, GetClassNameForSymbol(rule.symbol_name));
    new_grammar_rules.insert(new_grammar_rules.end(), new_ir_rules.begin(),
                             new_ir_rules.end());
  }
  grammar.rules.insert(grammar.rules.end(), new_grammar_rules.begin(),
                       new_grammar_rules.end());
  if (HasEOF(grammar)) {
    ProductionRule prod_rule = {{Block{
        Range::kNoRange, Terminal{TerminalType::kStringLiteral, "\"\""}}}};
    GrammarRule eof_rule =
        GrammarRule{"EOF", ProductionWithFallbackIndex{0, {prod_rule}}};
    grammar.rules.push_back(eof_rule);
  }
}

std::string CodeGenerator::Generate() {
  Preprocess(grammar_);
  constexpr absl::string_view kCodeTemplate =
      "#ifndef FUZZTEST_GRAMMARS_%1$s_GRAMMAR_H_\n"
      "#define "
      "FUZZTEST_GRAMMARS_%1$s_GRAMMAR_H_\n\n"
      "#include "
      "\"./fuzztest/internal/domains/in_grammar_impl.h\"\n\n"
      "namespace fuzztest::internal::grammar::%2$s {\n\n"
      "%3$s"
      "}     // namespace fuzztest::internal::grammar::%2$s\n"
      "namespace fuzztest::internal_no_adl{\n\n"
      "inline auto In%4$sGrammar() {"
      "return "
      "internal::grammar::InGrammarImpl<internal::grammar::%2$s::%4$sNode>();"
      "}\n\n"
      "}     // namespace fuzztest::internal_no_adl\n"
      "#endif  // "
      "FUZZTEST_GRAMMARS_%1$s_GRAMMAR_H_";

  CalculateFallBackIndex(grammar_.rules);
  std::string generated_code;

  std::string class_definitions;
  for (GrammarRule& rule : grammar_.rules) {
    absl::StrAppend(&class_definitions, BuildClassDefinitionForSymbol(rule));
  }

  for (auto& [literal, class_name] : literal_node_ids_) {
    absl::StrAppend(&class_definitions,
                    BuildClassDefinitionForLiteral(class_name));
  }

  for (auto& [charset, class_name] : charset_node_ids_) {
    absl::StrAppend(&class_definitions,
                    BuilldClassDefinitionForCharSet(class_name));
  }

  // The literals and charsets are collected when we build the definitions. So
  // the forward declaration has to be built after the definitions are built.
  std::string enum_for_ast_types;
  std::string forward_declaration;
  std::string string_literal_definitions;
  for (GrammarRule& rule : grammar_.rules) {
    absl::StrAppend(&forward_declaration, "class ",
                    GetClassNameForSymbol(rule.symbol_name), ";");
    absl::StrAppendFormat(&enum_for_ast_types, "k%s,",
                          GetClassNameForSymbol(rule.symbol_name));
  }
  for (auto& [content, class_name] : literal_node_ids_) {
    absl::StrAppend(&forward_declaration, "class ", class_name, ";");
    absl::StrAppendFormat(&string_literal_definitions,
                          "inline constexpr absl::string_view kStr%s = %s;",
                          class_name, content);
    absl::StrAppendFormat(&enum_for_ast_types, "k%s,", class_name);
  }
  for (auto& [content, class_name] : charset_node_ids_) {
    absl::StrAppend(&forward_declaration, "class ", class_name, ";");
    // We don't escape the charset so we use raw strings.
    absl::StrAppendFormat(
        &string_literal_definitions,
        "inline constexpr absl::string_view kStr%s = R\"grammar(%s)grammar\";",
        class_name, content);
    absl::StrAppendFormat(&enum_for_ast_types, "k%s,", class_name);
  }

  std::string captilialized_grammar_name = grammar_.grammar_name;
  captilialized_grammar_name[0] = toupper(captilialized_grammar_name[0]);

  enum_for_ast_types = absl::StrFormat(
      "enum %sTypes {%s};", captilialized_grammar_name, enum_for_ast_types);

  absl::StrAppend(&generated_code, enum_for_ast_types, forward_declaration,
                  "\n\n", string_literal_definitions, "\n\n",
                  class_definitions);

  std::string upper_grammar_name = absl::AsciiStrToUpper(grammar_.grammar_name);
  return absl::StrFormat(kCodeTemplate, upper_grammar_name,
                         grammar_.grammar_name, generated_code,
                         captilialized_grammar_name);
}

std::string CodeGenerator::BuildBaseTypeForGrammarRule(
    const GrammarRule& rule) {
  std::string class_name = GetClassNameForSymbol(rule.symbol_name);
  const std::vector<ProductionRule>& prod_rules =
      rule.productions.production_rules;
  FUZZTEST_INTERNAL_CHECK(!prod_rules.empty(), "No expansion!");
  if (prod_rules.size() > 1) {
    // This is a variant.
    std::vector<std::string> production_child_types;
    for (const ProductionRule& prod_rule : prod_rules) {
      FUZZTEST_INTERNAL_CHECK(prod_rule.blocks.size() == 1,
                              "Incorrect preprocess.");
      auto block = prod_rule.blocks[0];
      FUZZTEST_INTERNAL_CHECK(
          block.range == Range::kNoRange &&
              block.element.index() != BlockType::kSubProductions,
          "Incorrect preprocess.");
      production_child_types.push_back(GetClassName(block));
    }
    return absl::StrFormat("VariantDomain<k%s, %d, %s>", class_name,
                           *rule.productions.fallback_index,
                           absl::StrJoin(production_child_types, ","));
  } else if (prod_rules[0].blocks.size() == 1 &&
             prod_rules[0].blocks[0].range != Range::kNoRange) {
    // This is a vector.
    auto block = prod_rules[0].blocks[0];
    return WrapChildTypeWithRangedVector(class_name, GetClassName(block),
                                         block.range);
  } else {
    // This is a tuple.
    std::vector<std::string> production_child_types;
    auto blocks = prod_rules[0].blocks;
    for (const auto& block : blocks) {
      FUZZTEST_INTERNAL_CHECK(
          block.range == Range::kNoRange &&
              block.element.index() != BlockType::kSubProductions,
          "Incorrect preprocess.");
      production_child_types.push_back(GetClassName(block));
    }
    return absl::StrFormat("TupleDomain<k%s, %s>", class_name,
                           absl::StrJoin(production_child_types, ","));
  }
}

std::string CodeGenerator::BuildClassDefinitionForSymbol(GrammarRule& rule) {
  return absl::StrFormat("class %s final : public %s {};\n",
                         GetClassNameForSymbol(rule.symbol_name),
                         BuildBaseTypeForGrammarRule(rule));
}

std::string CodeGenerator::BuilldClassDefinitionForCharSet(
    absl::string_view class_name) {
  return absl::StrFormat(
      "class %s final: public RegexLiteralDomain<k%s, kStr%s> {};", class_name,
      class_name, class_name);
}

std::string CodeGenerator::BuildClassDefinitionForLiteral(
    absl::string_view class_name) {
  return absl::StrFormat(
      "class %s final: public StringLiteralDomain<k%s, kStr%s>{};", class_name,
      class_name, class_name);
}

// Caculate the fallback indexes for all the symbols (including
// sub-productions).
bool CodeGenerator::IsSymbolSafe(absl::string_view symbol) {
  return safe_rules_.find(symbol) != safe_rules_.end();
}

void CodeGenerator::MarkSymbolAsSafe(absl::string_view symbol) {
  safe_rules_.insert(std::string(symbol));
}

bool CodeGenerator::TryMarkProductionRuleVecAsSafe(
    ProductionWithFallbackIndex& productions) {
  std::vector<size_t> index_of_safe_productions;
  for (size_t i = 0; i < productions.production_rules.size(); ++i) {
    if (TryMarkProductionRuleAsSafe(productions.production_rules[i]))
      index_of_safe_productions.push_back(i);
  }
  if (index_of_safe_productions.empty()) return false;
  if (!productions.fallback_index.has_value())
    productions.fallback_index = index_of_safe_productions[0];
  return true;
}

// A range is safe if it allows the symbol to generate nothing.
bool CodeGenerator::HasSafeRange(const Block& block) {
  return block.range == Range::kOptional || block.range == Range::kUnlimited;
}

bool CodeGenerator::TryMarkBlockAsSafe(Block& block) {
  std::variant<Terminal, NonTerminal, ProductionWithFallbackIndex>& element =
      block.element;
  switch (element.index()) {
    case BlockType::kTerminal:
      return true;
    case BlockType::kNonTerminal:
      return IsSymbolSafe(std::get<BlockType::kNonTerminal>(element).name) ||
             HasSafeRange(block);
    case BlockType::kSubProductions: {
      bool is_safe = TryMarkProductionRuleVecAsSafe(
          std::get<BlockType::kSubProductions>(element));
      if (!is_safe && HasSafeRange(block)) {
        std::get<BlockType::kSubProductions>(element).fallback_index = 0;
        is_safe = true;
      }
      return is_safe;
    }
    default:
      FUZZTEST_INTERNAL_CHECK(false, "The execution should never reach here!");
  }
}

bool CodeGenerator::TryMarkProductionRuleAsSafe(ProductionRule& prod_rule) {
  for (Block& block : prod_rule.blocks) {
    if (!TryMarkBlockAsSafe(block)) return false;
  }
  return true;
}

bool CodeGenerator::TryMarkGrammarRuleAsSafe(GrammarRule& rule) {
  return TryMarkProductionRuleVecAsSafe(rule.productions);
}

void CodeGenerator::CalculateFallBackIndex(std::vector<GrammarRule>& rules) {
  std::vector<bool> safe_rule_indexes(rules.size(), false);
  bool has_change = true;
  do {
    has_change = false;
    for (size_t i = 0; i < rules.size(); ++i) {
      if (safe_rule_indexes[i]) continue;
      GrammarRule& rule = rules[i];
      if (TryMarkGrammarRuleAsSafe(rule)) {
        has_change = true;
        safe_rule_indexes[i] = true;
        MarkSymbolAsSafe(rule.symbol_name);
      }
    }
  } while (has_change);

  for (size_t i = 0; i < safe_rule_indexes.size(); ++i) {
    FUZZTEST_INTERNAL_CHECK(
        safe_rule_indexes[i],
        absl::StrCat("Some node is not safe: ", rules[i].symbol_name));
  }

  // Ensure that every sub-block is marked safe. For example, a grammar rule
  // is `expr: Literal | (expr '+' expr)`. This rule will be marked as safe
  // with fallback index as 0. However, the sub-block `(expr '+' expr)` is
  // not marked as safe yet. During code generation, it requires every
  // sub-block that is a variant must have a fallback index. Therefore, we
  // do an extra run of marking.
  for (GrammarRule& rule : rules) {
    TryMarkGrammarRuleAsSafe(rule);
  }
}

// Helper functions.

// Get the name of the generated class for the block.
std::string CodeGenerator::GetClassName(const Block& block) {
  switch (block.element.index()) {
    case BlockType::kTerminal: {
      const Terminal& terminal = std::get<BlockType::kTerminal>(block.element);
      return terminal.type == TerminalType::kStringLiteral
                 ? GetClassNameForLiteral(terminal.content)
                 : GetClassNameForCharSet(terminal.content);
    }
    case BlockType::kNonTerminal:
      return GetClassNameForSymbol(
          std::get<BlockType::kNonTerminal>(block.element).name);
    default:
      FUZZTEST_INTERNAL_CHECK(false, "A sub-block doesn't have a name!");
  }
  return "";
}

std::string CodeGenerator::GetClassNameForSymbol(std::string id) {
  FUZZTEST_INTERNAL_CHECK(!id.empty(), "Empty node name!");
  id[0] = toupper(id[0]);
  if (std::isdigit(id.back())) {
    return id;
  } else {
    return absl::StrFormat("%sNode", id);
  }
}

std::string CodeGenerator::GetClassNameForLiteral(absl::string_view s) {
  if (literal_node_ids_.find(s) == literal_node_ids_.end()) {
    literal_node_ids_[s] =
        absl::StrFormat("Literal%d", literal_node_ids_.size());
  }
  return literal_node_ids_[s];
}

std::string CodeGenerator::GetClassNameForCharSet(absl::string_view s) {
  if (charset_node_ids_.find(s) == charset_node_ids_.end()) {
    charset_node_ids_[s] =
        absl::StrFormat("CharSet%d", charset_node_ids_.size());
  }
  return charset_node_ids_[s];
}
};  // namespace fuzztest::internal::grammar
