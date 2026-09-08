# Copyright 2022 The Centipede Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Centipede puzzles.
# Simple fuzz targets used to test Centipede.
#
#  TODO(kcc): [impl] move all puzzles from ../BUILD here.
#  TODO(kcc): [impl] allow custom sancov flags.

load("@rules_cc//cc:cc_binary.bzl", "cc_binary")

# This is somewhat similar to libFuzzer puzzles:
# https://github.com/llvm/llvm-project/tree/main/compiler-rt/test/fuzzer
load(":puzzle.bzl", "puzzle")

licenses(["notice"])

package(default_visibility = ["@com_google_fuzztest//centipede/puzzles:__subpackages__"])

# The puzzles use a simple configuration language, see run_puzzle.sh.
[puzzle(name = n) for n in [
    "byte_cmp_4",
    "callstack",
    "deep_recursion",
    "memcmp_4",
    "memcmp_4_may_inline",
    "memcmp_3",
    "strcmp",
    "strcasecmp",
    "strncmp",
    "switch",
    "uint32_cmp_1",
    "oom",
    "per_input_timeout",
    "per_batch_timeout",
    "independent_compares",
    "autodictionary_stress",
    "paths",
    "thread_uint32_cmp_1",
    "pthread_exit_uint32_cmp_1",
]]

cc_binary(
    name = "test_oom",
    testonly = True,
    srcs = ["oom.cc"],
    # componentid = 1187448,  #Language Platforms > Sanitizers > Centipede
    # copts = copts,
    # features = features,
    # linkopts = linkopts,
    tags = [
        # Don't test this fuzz target on TAP or autofuzz, since this
        # target is for testing Centipede, not for fuzzing itself.
        "noautofuzz",
        "notap",
        "manual",  # don't run as part of blaze test.
        "guitar",  # allow capture by Guitar workflow queries.
    ],
    # target_compatible_with = select({
    #     "@platforms//os:macos": ["@platforms//os:macos"],
    #     "//conditions:default": ["@platforms//os:linux"],
    # }),
    deps = ["@com_google_fuzztest//centipede:centipede_runner"],
)
