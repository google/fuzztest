#include "./grammar_codegen/backend.h"

#include <string>

#include "gtest/gtest.h"
#include "./grammar_codegen/antlr_frontend.h"
#include "./grammar_codegen/grammar_info.h"

namespace fuzztest::internal::grammar {

namespace {

TEST(BackendTest, PreprocessInsertRuleForEOFAsNonTerminal) {
  const std::string grammar_str = R"(
                                grammar TEST_GRAMMAR;
                                root: "A" EOF;
                                )";
  GrammarInfoBuilder builder;
  Grammar grammar = builder.BuildGrammarInfo({grammar_str}, "test");
  CodeGenerator backend(grammar);
  backend.Preprocess(grammar);
  EXPECT_EQ(grammar.rules.back().symbol_name, "EOF");
}

TEST(BackendTest, PreprocessInsertRuleForEOFAsSubProduction) {
  const std::string kGrammar = R"foo(
                                grammar TEST_GRAMMAR;
                                root: "A" ("b" EOF)*;
                                )foo";
  GrammarInfoBuilder builder;
  Grammar grammar = builder.BuildGrammarInfo({kGrammar}, "test");
  CodeGenerator backend(grammar);
  backend.Preprocess(grammar);
  EXPECT_EQ(grammar.rules.back().symbol_name, "EOF");
}

}  // namespace

}  // namespace fuzztest::internal::grammar
