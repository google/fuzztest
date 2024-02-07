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

#include "./grammar_codegen/antlr_frontend.h"

#include <fstream>
#include <optional>
#include <streambuf>
#include <string>
#include <variant>
#include <vector>

#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "./grammar_codegen/generated_antlr_parser/ANTLRv4Lexer.h"
#include "./grammar_codegen/grammar_info.h"
#include "./fuzztest/internal/logging.h"

namespace fuzztest::internal::grammar {

namespace {

// The string literal in antlr4 is quote by '\'', we change it to '"'.
void ChangeStringQuote(std::string& str) {
  if (!str.empty() && str.front() == '\'' && str.back() == '\'') {
    str.front() = str.back() = '"';
  }
}

std::string EscapeString(absl::string_view text) {
  std::string excape_text;
  for (int i = 0; i < text.size(); ++i) {
    if (text[i] == '"' || text[i] == '\\') {
      excape_text.push_back('\\');
    }
    excape_text.push_back(text[i]);
  }
  ChangeStringQuote(excape_text);
  return excape_text;
}

// TODO(changochen): Handle Unicode.
// Add '^' to the char set if it is a NOT set.
std::string ConstructCharSetString(absl::string_view raw_str,
                                   bool is_not_set = false) {
  FUZZTEST_INTERNAL_CHECK(
      raw_str.size() > 2 && raw_str.front() == '[' && raw_str.back() == ']',
      "Passed argument is not a range string: `" + std::string(raw_str) + "`");
  std::string result(raw_str);
  if (is_not_set) {
    result = absl::StrFormat("[^%s]", result.substr(1, result.size() - 2));
  }
  return result;
}

// Returns a block representing a single space.
Block SpaceBlock() {
  Block block;
  auto& terminal = block.element.emplace<kTerminal>();
  terminal.type = TerminalType::kStringLiteral;
  terminal.content = "\" \"";
  return block;
}

}  // namespace

void GrammarInfoBuilder::enterLexerRuleSpec(
    ANTLRv4Parser::LexerRuleSpecContext* ctx) {
  rules_.push_back(ConstructGrammarRule(ctx));
}

void GrammarInfoBuilder::enterGrammarSpec(
    ANTLRv4Parser::GrammarSpecContext* ctx) {
  // A specification file can be for lexer, grammar or both. If it is not a
  // lexer specification file, it includes grammar and we use its name for the
  // namespace.
  if (ctx->grammarDecl()->grammarType()->LEXER() == nullptr) {
    grammar_name_ =
        absl::AsciiStrToLower(ctx->grammarDecl()->identifier()->getText());
  }
}

void GrammarInfoBuilder::enterParserRuleSpec(
    ANTLRv4Parser::ParserRuleSpecContext* ctx) {
  rules_.push_back(ConstructGrammarRule(ctx));
}

Block GrammarInfoBuilder::ConstructBlock(
    ANTLRv4Parser::LexerAtomContext* lexer_atom_ctx) {
  Block block;
  if (lexer_atom_ctx->terminal() && lexer_atom_ctx->terminal()->TOKEN_REF()) {
    auto k = block.element.emplace<kNonTerminal>(
        NonTerminal{lexer_atom_ctx->getText()});
    FUZZTEST_INTERNAL_CHECK(!k.name.empty(), "Empty name!");
  } else {
    auto& terminal = block.element.emplace<kTerminal>();
    std::string text = lexer_atom_ctx->getText();
    if (lexer_atom_ctx->terminal()) {
      terminal.content = EscapeString(text);
      terminal.type = TerminalType::kStringLiteral;
    } else if (lexer_atom_ctx->characterRange() ||
               lexer_atom_ctx->LEXER_CHAR_SET()) {
      terminal.type = TerminalType::kCharSet;
      terminal.content = ConstructCharSetString(lexer_atom_ctx->getText());
    } else if (lexer_atom_ctx->notSet()) {
      terminal.type = TerminalType::kCharSet;
      if (auto set_element_p = lexer_atom_ctx->notSet()->setElement()) {
        if (set_element_p->LEXER_CHAR_SET() ||
            set_element_p->STRING_LITERAL()) {
          terminal.content =
              ConstructCharSetString(set_element_p->getText(), true);
        } else {
          FUZZTEST_INTERNAL_CHECK(false, "Not lexer char set!");
        }
      } else {
        FUZZTEST_INTERNAL_CHECK(false, "Unhandled case!");
      }
    } else if (lexer_atom_ctx->DOT()) {
      terminal.type = TerminalType::kCharSet;
      terminal.content = EscapeString(lexer_atom_ctx->DOT()->getText());
    } else {
      FUZZTEST_INTERNAL_CHECK(false, "Unhandled case!");
    }
  }
  return block;
}

ProductionRule GrammarInfoBuilder::ConstructProductionRule(
    ANTLRv4Parser::LexerAltContext* ctx) {
  ProductionRule prod_rule;
  for (auto element : ctx->lexerElements()->lexerElement()) {
    Block block;
    if (element->lexerBlock() != NULL) {
      auto& sub_productions = block.element.emplace<2>();
      for (auto sub_rule : element->lexerBlock()->lexerAltList()->lexerAlt()) {
        sub_productions.production_rules.push_back(
            ConstructProductionRule(sub_rule));
      }
    } else if (element->lexerAtom() != NULL) {
      block = ConstructBlock(element->lexerAtom());
    } else {
      FUZZTEST_INTERNAL_CHECK(false, "Unhandled case!");
    }
    if (element->ebnfSuffix()) {
      block.range = ParseRange(element->ebnfSuffix()->getText());
    }
    prod_rule.blocks.push_back(std::move(block));
  }
  return prod_rule;
}

GrammarRule GrammarInfoBuilder::ConstructGrammarRule(
    ANTLRv4Parser::LexerRuleSpecContext* ctx) {
  GrammarRule grammar_rule;
  grammar_rule.symbol_name = ctx->TOKEN_REF()->getText();

  for (auto lexer_alt : ctx->lexerRuleBlock()->lexerAltList()->lexerAlt()) {
    grammar_rule.productions.production_rules.push_back(
        ConstructProductionRule(lexer_alt));
  }
  return grammar_rule;
}

Range GrammarInfoBuilder::ParseRange(absl::string_view s) {
  return (s == "?")                ? Range::kOptional
         : (s == "+" || s == "+?") ? Range::kNonEmpty
         : (s == "*" || s == "*?")
             ? Range::kUnlimited
             : (FUZZTEST_INTERNAL_CHECK(false,
                                        absl::StrCat("Unhandled case: ", s)),
                Range::kNoRange);
}

Block GrammarInfoBuilder::ConstructBlock(
    ANTLRv4Parser::BlockContext* block_ctx) {
  Block constructed_block;

  auto& sub_productions = constructed_block.element.emplace<kSubProductions>();
  for (auto sub_prod : block_ctx->altList()->alternative()) {
    sub_productions.production_rules.push_back(
        ConstructProductionRule(sub_prod));
  }
  return constructed_block;
}

Block GrammarInfoBuilder::ConstructBlock(ANTLRv4Parser::AtomContext* atom_ctx) {
  Block constructed_block;
  std::string node_name = atom_ctx->getText();
  if (atom_ctx->ruleref() ||
      (atom_ctx->terminal() && atom_ctx->terminal()->TOKEN_REF())) {
    constructed_block.element.emplace<kNonTerminal>(NonTerminal{node_name});
  } else if (atom_ctx->terminal()) {
    auto& terminal_node = constructed_block.element.emplace<kTerminal>();
    terminal_node.type = TerminalType::kStringLiteral;
    node_name = EscapeString(node_name);
    ChangeStringQuote(node_name);
    terminal_node.content = node_name;
  } else {
    FUZZTEST_INTERNAL_CHECK(false, "Unhandled case!");
  }
  return constructed_block;
}

Block GrammarInfoBuilder::ConstructBlock(
    ANTLRv4Parser::ElementContext* element) {
  Block constructed_block;
  std::optional<std::string> suffix;
  if (auto atom = element->atom()) {
    constructed_block = ConstructBlock(atom);
  } else if (auto ebnf = element->ebnf()) {
    constructed_block = ConstructBlock(ebnf->block());
    if (ebnf->blockSuffix()) {
      suffix = ebnf->blockSuffix()->getText();
    }
  } else if (auto labeled_element = element->labeledElement()) {
    if (labeled_element->atom()) {
      constructed_block = ConstructBlock(labeled_element->atom());
    } else if (labeled_element->block()) {
      constructed_block = ConstructBlock(labeled_element->block());
    } else {
      FUZZTEST_INTERNAL_CHECK(false, "Impossible case!");
    }
  } else {
    FUZZTEST_INTERNAL_CHECK(false, "Unhandled case!");
  }

  if (element->ebnfSuffix()) {
    FUZZTEST_INTERNAL_CHECK(!suffix.has_value(),
                            "It should have only one suffix.");
    suffix = element->ebnfSuffix()->getText();
  }

  if (suffix.has_value()) constructed_block.range = ParseRange(*suffix);
  return constructed_block;
}

ProductionRule GrammarInfoBuilder::ConstructProductionRule(
    ANTLRv4Parser::AlternativeContext* ctx) {
  ProductionRule prod_rule;
  for (int i = 0; i < ctx->element().size(); ++i) {
    prod_rule.blocks.push_back(ConstructBlock(ctx->element(i)));

    // If configured, insert a white space between blocks for a production rule.
    //
    // This is sometimes desired if the original grammar skips whitespaces but
    // we still want to generate whitespaces in the domain so that the lexer
    // can disambiguate some tokens, like keywords v.s. identifiers.
    if (insert_space_between_blocks_ && i != ctx->element().size() - 1) {
      prod_rule.blocks.push_back(SpaceBlock());
    }
  }
  return prod_rule;
}

GrammarRule GrammarInfoBuilder::ConstructGrammarRule(
    ANTLRv4Parser::ParserRuleSpecContext* pctx) {
  GrammarRule grammar_rule;
  grammar_rule.symbol_name = pctx->RULE_REF()->getText();
  auto labeledAlt_vec = pctx->ruleBlock()->ruleAltList()->labeledAlt();
  for (auto labeled_alt : pctx->ruleBlock()->ruleAltList()->labeledAlt()) {
    auto ctx = labeled_alt->alternative();
    FUZZTEST_INTERNAL_CHECK(ctx != nullptr, "Unhandeled case!");
    grammar_rule.productions.production_rules.push_back(
        ConstructProductionRule(ctx));
  }
  return grammar_rule;
}

Grammar GrammarInfoBuilder::BuildGrammarInfo(
    const std::vector<std::string>& input_grammar_specs,
    std::optional<std::string> grammar_name, bool insert_space_between_blocks) {
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(!input_grammar_specs.empty(),
                                       "No input files!");

  insert_space_between_blocks_ = insert_space_between_blocks;

  for (auto& input_grammar_spec : input_grammar_specs) {
    antlr4::ANTLRInputStream input(input_grammar_spec);
    antlr4_grammar::ANTLRv4Lexer lexer(&input);
    antlr4::CommonTokenStream tokens(&lexer);

    ANTLRv4Parser parser(&tokens);
    try {
      antlr4::tree::ParseTree* tree = parser.grammarSpec();
      antlr4::tree::ParseTreeWalker::DEFAULT.walk(this, tree);
    } catch (antlr4::ParseCancellationException) {
      FUZZTEST_INTERNAL_CHECK(false, "Cannot parse the grammar files!");
    } catch (...) {
      // The ParseCancellationException might miss some errors. So we need to
      // catch everything here.
      FUZZTEST_INTERNAL_CHECK(false, "Unknown errors!");
    }
  }
  if (grammar_name.has_value()) {
    grammar_name_ = *grammar_name;
  }
  FUZZTEST_INTERNAL_CHECK(!grammar_name_.empty() && !rules_.empty(),
                          "Wrong grammar file!");
  return Grammar{std::move(grammar_name_), std::move(rules_)};
}

}  // namespace fuzztest::internal::grammar
