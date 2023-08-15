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

# Commonly used grammars.

load(
    "//build_defs:cc_fuzztest_grammar_library.bzl",
    "cc_fuzztest_grammar_library",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

exports_files(["JSON.g4"])

cc_fuzztest_grammar_library(
    name = "json_grammar",
    srcs = ["JSON.g4"],
    top_level_rule = "json",
)
