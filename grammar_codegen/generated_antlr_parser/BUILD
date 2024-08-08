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

# Generated parser for antlr4 grammar.

package(default_visibility = ["@com_google_fuzztest//grammar_codegen:__pkg__"])

licenses(["notice"])

cc_library(
    name = "generated_antlr_parser",
    srcs = [
        "ANTLRv4Lexer.cpp",
        "ANTLRv4Parser.cpp",
        "ANTLRv4ParserBaseListener.cpp",
        "ANTLRv4ParserListener.cpp",
    ],
    hdrs = [
        "ANTLRv4Lexer.h",
        "ANTLRv4Parser.h",
        "ANTLRv4ParserBaseListener.h",
        "ANTLRv4ParserListener.h",
    ],
    copts = [
        "-fexceptions",
        # FIXME: antlr generates broken C++ code that attempts to construct
        # a std::string from nullptr. It's not clear whether the relevant
        # constructs are reachable.
        "-Wno-nonnull",
    ],
    features = ["-use_header_modules"],  # Incompatible with -fexceptions.
    deps = ["@antlr_cpp//:antlr4-cpp-runtime"],
)
