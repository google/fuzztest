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

"""BUILD rule for Centipede puzzles"""

load("@rules_cc//cc:cc_test.bzl", "cc_test")
load("@com_google_fuzztest//centipede/testing:build_defs.bzl", "centipede_fuzz_target")

def puzzle(name, tags = []):
    """Generates a cc_fuzz_target target instrumented with sancov and a sh script to run it.

    Args:
      name: A unique name for this target
      tags: Tags for this target
    """

    centipede_fuzz_target(
        name = name,
        deps = [
            "@abseil-cpp//absl/base:nullability",
        ],
    )

    # We test every puzzle with two different seeds so that the result is more
    # trustworthy. The seeds are fixed so that we have some degree of
    # repeatability. Each sh_test performs a single run with a single seed, so
    # that the log is minimal.
    for seed in ["1", "2"]:
        cc_test(
            name = "run_" + seed + "_" + name,
            srcs = ["run_puzzle.cc"],
            args = ["--seed=" + seed, "--puzzle=" + name],
            data = [
                ":" + name,
                name + ".cc",
                "@com_google_fuzztest//centipede:centipede_uninstrumented",
            ],
            deps = [
                "@googletest//:gtest",
                "@abseil-cpp//absl/flags:flag",
                "@abseil-cpp//absl/flags:parse",
                "@abseil-cpp//absl/strings",
                "@abseil-cpp//absl/time",
                "@com_google_fuzztest//centipede:command",
                "@com_google_fuzztest//common:logging",
                "@com_google_fuzztest//common:test_util",
            ],
            tags = tags,
        )
