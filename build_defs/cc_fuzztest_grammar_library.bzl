# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Build rules to create cc_library that implements the InGrammar domain for a
given grammar from an ANTLRv4 grammar specification."""

def cc_fuzztest_grammar_library(name, srcs, top_level_rule = None):
    """Generates the C++ library corresponding to an antlr4 grammar specification.

    Args:

      name: The name of the package to use for the cc_library. For example:
        `"json_grammar"`.
      srcs: The grammar specification files in ANTRLv4 format. For example:
        `["json.g4"]`.
      top_level_rule: The top level rule of the grammar that we use to generate
        sentences. It will also be used in the generated domain name. For
        example, if you set `top_level_rule="json"`, the generated domain name
        will be `InJsonDomain` and it generates strings starting from the rule
        `json` in your grammar file.

    """

    output_file_name = name + ".h"
    cmd = "$(location //tools:grammar_domain_code_generator)" + \
          " --output_header_file_path " + "$(@D)/" + output_file_name + \
          " --input_grammar_files " + "`echo $(SRCS) | tr ' ' ','`"
    if top_level_rule:
        cmd += " --top_level_rule " + top_level_rule

    native.genrule(
        name = name + "_source",
        srcs = srcs,
        outs = [output_file_name],
        cmd = cmd,
        heuristic_label_expansion = False,
        tools = ["//tools:grammar_domain_code_generator"],
    )

    native.cc_library(
        name = name,
        hdrs = [output_file_name],
        deps = ["//fuzztest:domain"],
    )
