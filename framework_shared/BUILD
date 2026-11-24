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

# Shared runtime, crash reporting, and coverage libraries used by both the
# C++ and Rust FuzzTest frameworks.

load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

DEFAULT_VISIBILITY = ["@com_google_fuzztest//:__subpackages__"]

package(default_visibility = DEFAULT_VISIBILITY)

licenses(["notice"])

# Centipede runner needs access to this file until it depends on
# :sancov_runtime (b/436308818).
exports_files(
    srcs = ["sancov_runtime.h"],
    visibility = ["@com_google_fuzztest//centipede:__pkg__"],
)

# TODO(b/436366556): Remove and replace once this is standardized.
DISABLE_SANCOV_COPTS = [
    "-fsanitize-coverage=0",
]

cc_library(
    name = "sancov_runtime",
    srcs = [
        "@com_google_fuzztest//centipede:pc_info.h",
        "@com_google_fuzztest//common:defs.h",
        "@com_google_fuzztest//framework_shared/internal:coverage_interceptors.cc",
        "@com_google_fuzztest//framework_shared/internal:reverse_pc_table.h",
        "@com_google_fuzztest//framework_shared/internal:runner_dl_info.cc",
        "@com_google_fuzztest//framework_shared/internal:runner_dl_info.h",
        "@com_google_fuzztest//framework_shared/internal:runtime_interceptors.cc",
        "@com_google_fuzztest//framework_shared/internal:sancov_callbacks.cc",
        "@com_google_fuzztest//framework_shared/internal:sancov_object_array.cc",
        "@com_google_fuzztest//framework_shared/internal:sancov_object_array.h",
        "@com_google_fuzztest//framework_shared/internal:sancov_state.cc",
        "@com_google_fuzztest//framework_shared/internal:sancov_state.h",
    ],
    hdrs = [
        "sancov_runtime.h",
    ],
    copts = DISABLE_SANCOV_COPTS,
    deps = [
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/base:nullability",
        "@abseil-cpp//absl/numeric:bits",
        "@abseil-cpp//absl/types:span",
        "@com_google_fuzztest//centipede:engine_abi",
        "@com_google_fuzztest//centipede:feature",
        "@com_google_fuzztest//framework_shared/internal:callstack",
        "@com_google_fuzztest//framework_shared/internal:execution_metadata",
        "@com_google_fuzztest//framework_shared/internal:foreach_nonzero",
        "@com_google_fuzztest//framework_shared/internal:int_utils",
        "@com_google_fuzztest//framework_shared/internal:interceptor_utils",
        "@com_google_fuzztest//framework_shared/internal:runner_cmp_trace",
        "@com_google_fuzztest//framework_shared/internal:sancov_utils",
    ],
)

cc_library(
    name = "crash_reporting",
    srcs = ["crash_reporting.cc"],
    hdrs = ["crash_reporting.h"],
    # Link statically and unconditionally into the main executable so the
    # strong sanitizer error summary hook overrides the default weak definition
    # in the sanitizer runtime (which is also linked statically into the
    # executable).
    linkstatic = True,
    deps = [
        "@abseil-cpp//absl/base:config",
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/debugging:stacktrace",
        "@abseil-cpp//absl/debugging:symbolize",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/types:span",
        "@com_google_fuzztest//common:logging",
        "@com_google_fuzztest//framework_shared/internal:symbol_name_utils",
    ] + select({
        "//conditions:default": [],
    }),
    alwayslink = True,
)

cc_test(
    name = "crash_reporting_test",
    srcs = ["crash_reporting_test.cc"],
    deps = [
        ":crash_reporting",
        "@abseil-cpp//absl/base:config",
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/types:span",
        "@googletest//:gtest_main",
    ],
)
