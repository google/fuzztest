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

load("@com_google_fuzztest//centipede/testing:build_defs.bzl", "centipede_fuzz_target")

def puzzle(name):
    """Generates a cc_fuzz_target target instrumented with sancov and a sh script to run it.

    Args:
      name: A unique name for this target
    """

    centipede_fuzz_target(
        name = name,
    )

    # We test every puzzle with two different seeds so that the result is more
    # trustworthy. The seeds are fixed so that we have some degree of
    # repeatability. Each sh_test performs a single run with a single seed, so
    # that the log is minimal.
    for seed in ["1", "2"]:
        native.sh_test(
            name = "run_" + seed + "_" + name,
            srcs = ["run_puzzle.sh"],
            data = [
                ":" + name,
                name + ".cc",
                "@com_google_fuzztest//centipede",
                "@com_google_fuzztest//centipede:test_util_sh",
            ],
        )
