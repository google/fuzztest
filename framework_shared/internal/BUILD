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

# Internal implementation libraries and sources backing
# @com_google_fuzztest//framework_shared.

load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

DEFAULT_VISIBILITY = [
    "@com_google_fuzztest//framework_shared:__pkg__",
]

package(default_visibility = DEFAULT_VISIBILITY)

licenses(["notice"])

# Compiled directly by @com_google_fuzztest//framework_shared:sancov_runtime.
exports_files(
    srcs = [
        "coverage_interceptors.cc",
        "reverse_pc_table.h",
        # TODO(b/587478278): Rename legacy runner_* files.
        "runner_dl_info.cc",
        "runner_dl_info.h",
        "runtime_interceptors.cc",
        "sancov_callbacks.cc",
        "sancov_object_array.cc",
        "sancov_object_array.h",
        "sancov_state.cc",
        "sancov_state.h",
    ],
    visibility = DEFAULT_VISIBILITY,
)

# TODO(b/436366556): Remove and replace once this is standardized.
DISABLE_SANCOV_COPTS = [
    "-fsanitize-coverage=0",
]

cc_library(
    name = "callstack",
    hdrs = ["callstack.h"],
    copts = DISABLE_SANCOV_COPTS,
    # Avoid non-trivial dependencies here, as this library will be linked to target binaries.
    deps = [
        ":rolling_hash",
    ],
)

cc_test(
    name = "callstack_test",
    srcs = ["callstack_test.cc"],
    deps = [
        ":callstack",
        "@abseil-cpp//absl/base:nullability",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@com_google_fuzztest//common:defs",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "crash_reporting_internal",
    hdrs = ["crash_reporting_internal.h"],
    deps = [
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_library(
    name = "execution_metadata",
    srcs = ["execution_metadata.cc"],
    hdrs = ["execution_metadata.h"],
    copts = DISABLE_SANCOV_COPTS,
    visibility = DEFAULT_VISIBILITY + [
        "@com_google_fuzztest//centipede:__pkg__",
        "@com_google_fuzztest//fuzztest/internal:__pkg__",
    ],
    deps = [
        # This target must have a minimal set of dependencies since it is
        # used in centipede_runner.
        "@com_google_fuzztest//common:defs",
    ],
)

cc_test(
    name = "execution_metadata_test",
    srcs = ["execution_metadata_test.cc"],
    deps = [
        ":execution_metadata",
        "@com_google_fuzztest//common:defs",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "foreach_nonzero",
    hdrs = ["foreach_nonzero.h"],
    copts = DISABLE_SANCOV_COPTS,
)

cc_test(
    name = "foreach_nonzero_test",
    srcs = ["foreach_nonzero_test.cc"],
    deps = [
        ":foreach_nonzero",
        "@googletest//:gtest_main",
    ],
)

# This lib must have zero non-trivial dependencies (other than libc).
cc_library(
    name = "int_utils",
    hdrs = ["int_utils.h"],
    copts = DISABLE_SANCOV_COPTS,
)

cc_test(
    name = "int_utils_test",
    srcs = ["int_utils_test.cc"],
    deps = [
        ":int_utils",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "interceptor_utils",
    hdrs = ["interceptor_utils.h"],
    copts = DISABLE_SANCOV_COPTS,
    linkopts = ["-ldl"],  # for dlsym
)

cc_library(
    name = "reverse_pc_table",
    hdrs = ["reverse_pc_table.h"],
    visibility = ["//visibility:private"],
    # Avoid non-trivial dependencies here, as this library will be linked to target binaries.
    deps = ["@com_google_fuzztest//centipede:pc_info"],
)

cc_test(
    name = "reverse_pc_table_test",
    srcs = ["reverse_pc_table_test.cc"],
    deps = [
        ":reverse_pc_table",
        "@com_google_fuzztest//centipede:pc_info",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "rolling_hash",
    hdrs = ["rolling_hash.h"],
    copts = DISABLE_SANCOV_COPTS,
    # Used by centipede:feature (hashed_ring_buffer.h).
    visibility = DEFAULT_VISIBILITY + [
        "@com_google_fuzztest//centipede:__pkg__",
    ],
)

cc_test(
    name = "rolling_hash_test",
    srcs = ["rolling_hash_test.cc"],
    deps = [
        ":rolling_hash",
        "@com_google_fuzztest//centipede:feature",
        "@googletest//:gtest_main",
    ],
)

# TODO(b/587478278): Rename legacy runner_* targets and files.
cc_library(
    name = "runner_cmp_trace",
    hdrs = ["runner_cmp_trace.h"],
    copts = DISABLE_SANCOV_COPTS,
    # Used by centipede:byte_array_mutator_test.
    visibility = DEFAULT_VISIBILITY + [
        "@com_google_fuzztest//centipede:__pkg__",
    ],
    deps = ["@abseil-cpp//absl/base:core_headers"],
)

cc_test(
    name = "runner_cmp_trace_test",
    srcs = ["runner_cmp_trace_test.cc"],
    deps = [
        ":runner_cmp_trace",
        "@abseil-cpp//absl/base:nullability",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "runtime_interceptors_test",
    srcs = ["runtime_interceptors_test.cc"],
    deps = [
        "@com_google_fuzztest//common:logging",
        "@com_google_fuzztest//framework_shared:sancov_runtime",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "sancov_utils",
    srcs = ["sancov_utils.cc"],
    hdrs = ["sancov_utils.h"],
    copts = DISABLE_SANCOV_COPTS,
    deps = [
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/base:nullability",
    ],
)

cc_library(
    name = "symbol_name_utils",
    hdrs = ["symbol_name_utils.h"],
    # Used by internal:type_support.
    visibility = DEFAULT_VISIBILITY + [
        "@com_google_fuzztest//fuzztest/internal:__pkg__",
    ],
    deps = ["@abseil-cpp//absl/strings:string_view"],
)
