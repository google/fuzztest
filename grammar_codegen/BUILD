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

# Code generation library for grammar support.

package(default_visibility = ["@com_google_fuzztest//tools:__pkg__"])

licenses(["notice"])

cc_library(
    name = "antlr_frontend",
    srcs = ["antlr_frontend.cc"],
    hdrs = ["antlr_frontend.h"],
    copts = [
        "-g",
        "-fexceptions",
    ],
    features = ["-use_header_modules"],  # Incompatible with -fexceptions.
    deps = [
        ":grammar_info",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@com_google_fuzztest//fuzztest/internal:logging",
        "@com_google_fuzztest//grammar_codegen/generated_antlr_parser",
    ],
)

cc_library(
    name = "backend",
    srcs = ["backend.cc"],
    hdrs = ["backend.h"],
    deps = [
        ":grammar_info",
        "@abseil-cpp//absl/container:btree",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@com_google_fuzztest//fuzztest/internal:logging",
    ],
)

cc_test(
    name = "backend_test",
    srcs = ["backend_test.cc"],
    deps = [
        ":antlr_frontend",
        ":backend",
        ":grammar_info",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "code_generation",
    srcs = ["code_generation.cc"],
    hdrs = ["code_generation.h"],
    deps = [
        ":antlr_frontend",
        ":backend",
    ],
)

cc_test(
    name = "code_generation_test",
    srcs = ["code_generation_test.cc"],
    data = [
        "testdata/expected_json_grammar.h",
        "testdata/expected_json_grammar_with_spaces.h",
        "@com_google_fuzztest//fuzztest/grammars:JSON.g4",
    ],
    deps = [
        ":code_generation",
        "@abseil-cpp//absl/strings",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "grammar_info",
    hdrs = ["grammar_info.h"],
)
