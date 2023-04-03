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

# Build file for the dso_example

# Shared library that we want to fuzz, built with (some) coverage instrumentation.
# It has unresolved instrumentation symbol(s) which will be resolved dynamically.
cc_binary(
    name = "fuzz_me.so",
    srcs = ["fuzz_me.cc"],
    copts = ["-fsanitize-coverage=trace-pc"],
    linkshared = True,
    linkstatic = False,
)

# The main binary that calls into :fuzz_me, which is linked dynamically.
# Not instrumented with coverage.
cc_binary(
    name = "main",
    srcs = [
        "main.cc",
        ":fuzz_me.so",
    ],
    linkopts = ["-ldl"],
    linkstatic = False,
    deps = [
        "@com_google_fuzztest//centipede:centipede_runner_no_main",  # build-cleaner:keep
    ],
)

# The main binary which dlopen-s fuzz_me and then calls FuzzMe.
cc_binary(
    name = "main_with_dlopen",
    srcs = ["main.cc"],
    linkopts = ["-ldl"],
    linkstatic = False,
)

sh_test(
    name = "dso_example_test",
    srcs = ["dso_example_test.sh"],
    data = [
        ":fuzz_me.so",
        ":main",
        ":main_with_dlopen",
        "@com_google_fuzztest//centipede",
        "@com_google_fuzztest//centipede:centipede_runner_no_main.so",
    ],
    deps = [
        "@com_google_fuzztest//centipede:test_util_sh",
    ],
)
