# Copyright 2026 Google LLC
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

# Shared engine ABI, controller, and worker libraries used by both the C++ and
# Rust FuzzTest frameworks.

load("@rules_cc//cc:cc_library.bzl", "cc_library")  # @unused buildcleaner: keep

DEFAULT_VISIBILITY = ["//visibility:public"]

package(default_visibility = DEFAULT_VISIBILITY)

licenses(["notice"])

### Libraries

# TODO: b/436366556 - Remove and replace once this is standardized.
DISABLE_SANCOV_COPTS = [
    "-fsanitize-coverage=0",
]

# Disable sancov and sanitizer instrumentation.
#
# Need to allow MSAN to avoid false positives when interacting with dependencies.
RUNNER_COPTS = [
    "-fsanitize-coverage=0",
    "-fno-sanitize=address,hwaddress,thread,undefined",
]

cc_library(
    name = "engine_abi",
    hdrs = ["engine_abi.h"],
)

cc_library(
    name = "engine_controller_with_subprocess",
    srcs = ["engine_controller_with_subprocess.cc"],
    hdrs = ["engine_controller_abi.h"],
    data = select({
        "@com_google_fuzztest//centipede:is_controller_binary_bundled": [
            "@com_google_fuzztest//centipede:centipede_uninstrumented",
        ],
        "//conditions:default": [],
    }),
    deps = [
        ":engine_abi",
        "@com_google_fuzztest//rust_cpp_common:escaping",
    ],
)

cc_library(
    name = "engine_worker",
    srcs = [
        "engine_worker.cc",
    ],
    hdrs = ["engine_worker_abi.h"],
    copts = RUNNER_COPTS,
    deps = [
        ":engine_abi",
        ":runner_request",
        "@abseil-cpp//absl/base:nullability",
        "@com_google_fuzztest//centipede:feature",
        "@com_google_fuzztest//centipede:runner_fork_server",
        "@com_google_fuzztest//centipede:runner_result",
        "@com_google_fuzztest//common:defs",
        "@com_google_fuzztest//rust_cpp_common:execution_metadata",
        "@com_google_fuzztest//rust_cpp_common:runner_utils",
        "@com_google_fuzztest//rust_cpp_common:shared_memory_blob_sequence",
    ],
)

cc_library(
    name = "runner_request",
    srcs = ["runner_request.cc"],
    hdrs = ["runner_request.h"],
    copts = DISABLE_SANCOV_COPTS,
    deps = [
        # This target must have a minimal set of dependencies since it is
        # used in centipede_runner.
        "@abseil-cpp//absl/types:span",
        "@com_google_fuzztest//centipede:mutation_data",
        "@com_google_fuzztest//common:defs",
        "@com_google_fuzztest//rust_cpp_common:execution_metadata",
        "@com_google_fuzztest//rust_cpp_common:shared_memory_blob_sequence",
    ],
)
