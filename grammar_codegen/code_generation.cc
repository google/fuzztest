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

#include "./grammar_codegen/code_generation.h"

#include <optional>
#include <string>
#include <vector>

#include "./grammar_codegen/backend.h"

namespace fuzztest::internal::grammar {

std::string GenerateGrammarHeader(
    const std::vector<std::string>& input_grammar_specs,
    std::optional<std::string> grammar_name, bool insert_space_between_blocks) {
  GrammarInfoBuilder builder;
  CodeGenerator backend(builder.BuildGrammarInfo(
      input_grammar_specs, grammar_name, insert_space_between_blocks));
  return backend.Generate();
}
}  // namespace fuzztest::internal::grammar
