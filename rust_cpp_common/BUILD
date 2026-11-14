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

# Shared libraries used by both the C++ and Rust FuzzTest frameworks.

load("@rules_cc//cc:cc_library.bzl", "cc_library")  # @unused buildcleaner: keep
load("@rules_cc//cc:cc_test.bzl", "cc_test")

DEFAULT_VISIBILITY = ["//visibility:public"]

package(default_visibility = DEFAULT_VISIBILITY)

licenses(["notice"])

### Libraries

# TODO: b/436366556 - Remove and replace once this is standardized.
DISABLE_SANCOV_COPTS = [
    "-fsanitize-coverage=0",
]

cc_library(
    name = "escaping",
    srcs = ["escaping.cc"],
    hdrs = ["escaping.h"],
    deps = ["@abseil-cpp//absl/strings"],
)

cc_library(
    name = "execution_metadata",
    srcs = ["execution_metadata.cc"],
    hdrs = ["execution_metadata.h"],
    copts = DISABLE_SANCOV_COPTS,
    deps = [
        # This target must have a minimal set of dependencies since it is
        # used in centipede_runner.
        ":shared_memory_blob_sequence",
        "@com_google_fuzztest//common:defs",
    ],
)

cc_library(
    name = "runner_utils",
    srcs = ["runner_utils.cc"],
    hdrs = ["runner_utils.h"],
    copts = DISABLE_SANCOV_COPTS,
    deps = [
        "@abseil-cpp//absl/base:nullability",
    ],
)

cc_library(
    name = "shared_memory_blob_sequence",
    srcs = ["shared_memory_blob_sequence.cc"],
    hdrs = ["shared_memory_blob_sequence.h"],
    copts = DISABLE_SANCOV_COPTS,
    linkopts = select({
        "@platforms//os:macos": [],
        "//conditions:default": [
            "-lrt",  # for shm_open
        ],
    }),
    deps = ["@abseil-cpp//absl/base:nullability"],
    # don't add any dependencies.
)

### Tests

cc_test(
    name = "execution_metadata_test",
    srcs = ["execution_metadata_test.cc"],
    deps = [
        ":execution_metadata",
        ":shared_memory_blob_sequence",
        "@com_google_fuzztest//common:defs",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "runner_utils_test",
    srcs = ["runner_utils_test.cc"],
    deps = [
        ":runner_utils",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "shared_memory_blob_sequence_test",
    srcs = ["shared_memory_blob_sequence_test.cc"],
    deps = [
        ":shared_memory_blob_sequence",
        "@googletest//:gtest_main",
    ],
)
