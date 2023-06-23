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

# Description:
#   Centipede: an experimental distributed fuzzing engine.

load(":instrument.bzl", "cc_uninstrumented_binary")

VISIBILITY = ["//visibility:public"]

TEMP_EXTENDED_VISIBILITY = VISIBILITY

PUBLIC_API_VISIBILITY = VISIBILITY

package(default_visibility = VISIBILITY)

licenses(["notice"])

################################################################################
#                                  Binaries
################################################################################

cc_binary(
    name = "centipede",
    srcs = ["centipede_main.cc"],
    deps = [
        ":centipede_default_callbacks",
        ":centipede_interface",
        ":config_file",
        ":environment",
        # When Centipede is built as a data dependency of the runner target,
        # there may be residual sancov instrumentation whose symbols must still
        # be defined.
        ":weak_sancov_stubs",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:globals",
        "@com_google_absl//absl/log:initialize",
    ],
)

cc_uninstrumented_binary(
    name = "centipede_uninstrumented",
    binary = ":centipede",
)

################################################################################
#                             C++ libraries
################################################################################

# This lib must have zero non-trivial dependencies (other than libc).
cc_library(
    name = "int_utils",
    hdrs = ["int_utils.h"],
)

cc_library(
    name = "rolling_hash",
    hdrs = ["rolling_hash.h"],
    deps = [
        "@com_google_absl//absl/base:core_headers",  # exception, ok to depend on here.
    ],
)

cc_library(
    name = "foreach_nonzero",
    hdrs = ["foreach_nonzero.h"],
)

# This lib must have zero non-trivial dependencies (other than libc). See feature.h.
cc_library(
    name = "feature",
    srcs = ["feature.cc"],
    hdrs = [
        "concurrent_bitset.h",  # TODO(kcc): consider moving to a separate cc_library.
        "concurrent_byteset.h",  # TODO(kcc): consider moving to a separate cc_library.
        "feature.h",
        "hashed_ring_buffer.h",  # TODO(kcc): consider moving to a separate cc_library.
    ],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        ":int_utils",
        ":rolling_hash",
        "@com_google_absl//absl/base:core_headers",  # exception, ok to depend on here.
    ],
)

cc_library(
    name = "pc_info",
    hdrs = ["pc_info.h"],
)

cc_library(
    name = "logging",
    srcs = ["logging.cc"],
    hdrs = ["logging.h"],
    deps = [
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
    ],
)

cc_library(
    name = "knobs",
    srcs = ["knobs.cc"],
    hdrs = ["knobs.h"],
    # Avoid non-trivial dependencies here, as this library will be linked to target binaries.
    deps = [
        ":defs",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "reverse_pc_table",
    hdrs = ["reverse_pc_table.h"],
    # Avoid non-trivial dependencies here, as this library will be linked to target binaries.
    deps = [
        ":pc_info",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "callstack",
    hdrs = ["callstack.h"],
    # Avoid non-trivial dependencies here, as this library will be linked to target binaries.
    deps = [
        ":rolling_hash",
    ],
)

# simple definitions only, no code, no deps other than span.
cc_library(
    name = "defs",
    hdrs = ["defs.h"],
    visibility = PUBLIC_API_VISIBILITY,
    deps = ["@com_google_absl//absl/types:span"],
)

# Various utilities.
cc_library(
    name = "util",
    srcs = [
        "hash.cc",
        "util.cc",
    ],
    hdrs = ["util.h"],
    linkopts = ["-Wl,-Bstatic -lcrypto -Wl,-Bdynamic -ldl"],
    visibility = TEMP_EXTENDED_VISIBILITY,
    deps = [
        ":defs",
        ":feature",
        ":logging",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "config_util",
    srcs = ["config_util.cc"],
    hdrs = ["config_util.h"],
    deps = [
        "@com_google_absl//absl/flags:reflection",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "config_file",
    srcs = ["config_file.cc"],
    hdrs = ["config_file.h"],
    visibility = TEMP_EXTENDED_VISIBILITY,
    deps = [
        ":config_util",
        ":logging",
        ":remote_file",
        ":util",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/flags:reflection",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "rusage_stats",
    srcs = ["rusage_stats.cc"],
    hdrs = ["rusage_stats.h"],
    visibility = ["//visibility:public"],
    deps = [
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
    ],
)

cc_library(
    name = "rusage_profiler",
    srcs = ["rusage_profiler.cc"],
    hdrs = ["rusage_profiler.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":rusage_stats",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
    ],
)

cc_library(
    name = "stats",
    srcs = ["stats.cc"],
    hdrs = ["stats.h"],
    deps = [
        ":environment",
        ":logging",
        ":remote_file",
        "@com_google_absl//absl/container:btree",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "minimize_crash",
    srcs = ["minimize_crash.cc"],
    hdrs = ["minimize_crash.h"],
    deps = [
        ":centipede_callbacks",
        ":defs",
        ":environment",
        ":logging",
        ":util",
        "@com_google_absl//absl/synchronization",
    ],
)

cc_library(
    name = "analyze_corpora",
    srcs = ["analyze_corpora.cc"],
    hdrs = ["analyze_corpora.h"],
    deps = [
        ":binary_info",
        ":control_flow",
        ":corpus",
        ":feature",
        ":logging",
        "@com_google_absl//absl/container:flat_hash_set",
    ],
)

cc_library(
    name = "blob_file",
    srcs = ["blob_file.cc"],
    hdrs = ["blob_file.h"],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        ":defs",
        ":logging",
        ":remote_file",
        ":util",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "shared_memory_blob_sequence",
    srcs = ["shared_memory_blob_sequence.cc"],
    hdrs = ["shared_memory_blob_sequence.h"],
    linkopts = ["-lrt"],  # for shm_open.
    # don't add any dependencies.
)

cc_library(
    name = "execution_result",
    srcs = ["execution_result.cc"],
    hdrs = ["execution_result.h"],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        # This target must have a minimal set of dependencies since it is
        # used in centipede_runner.
        ":feature",
        ":runner_cmp_trace",
        ":shared_memory_blob_sequence",
    ],
)

cc_library(
    name = "execution_request",
    srcs = ["execution_request.cc"],
    hdrs = ["execution_request.h"],
    deps = [
        # This target must have a minimal set of dependencies since it is
        # used in centipede_runner.
        ":shared_memory_blob_sequence",
        ":defs",
    ],
)

cc_library(
    name = "byte_array_mutator",
    srcs = ["byte_array_mutator.cc"],
    hdrs = ["byte_array_mutator.h"],
    visibility = PUBLIC_API_VISIBILITY,
    # Avoid non-trivial dependencies here, as this library will be linked to target binaries.
    deps = [
        ":defs",
        ":knobs",
    ],
)

# Library for dealing with code coverage data from
# https://clang.llvm.org/docs/SanitizerCoverage.html.
cc_library(
    name = "coverage",
    srcs = [
        "coverage.cc",
        "symbol_table.cc",
    ],
    hdrs = [
        "coverage.h",
        "symbol_table.h",
    ],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        ":command",
        ":control_flow",
        ":defs",
        ":feature",
        ":logging",
        ":util",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
    ],
)

# Library for dealing with control flow data from
# https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-control-flow.
cc_library(
    name = "control_flow",
    srcs = [
        "control_flow.cc",
        "symbol_table.cc",
    ],
    hdrs = [
        "control_flow.h",
        "symbol_table.h",
    ],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        ":command",
        ":defs",
        ":logging",
        ":pc_info",
        ":util",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/strings",
    ],
)

# Library for dealing with call graph data from
# https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-control-flow.
cc_library(
    name = "call_graph",
    srcs = [
        "call_graph.cc",
    ],
    hdrs = [
        "call_graph.h",
    ],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        ":control_flow",
        ":logging",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/log:check",
    ],
)

cc_library(
    name = "remote_file",
    srcs = ["remote_file.cc"],
    hdrs = ["remote_file.h"],
    deps = [
        ":defs",
        ":logging",
        "@com_google_absl//absl/base:core_headers",
    ],
)

cc_library(
    name = "feature_set",
    srcs = ["feature_set.cc"],
    hdrs = ["feature_set.h"],
    deps = [
        ":coverage",
        ":defs",
        ":feature",
        ":util",
        "@com_google_absl//absl/container:flat_hash_set",
    ],
)

# TODO(kcc): [impl] add dedicated unittests.
cc_library(
    name = "corpus",
    srcs = ["corpus.cc"],
    hdrs = ["corpus.h"],
    deps = [
        ":binary_info",
        ":control_flow",
        ":coverage",
        ":defs",
        ":feature",
        ":feature_set",
        ":util",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "command",
    srcs = ["command.cc"],
    hdrs = ["command.h"],
    visibility = TEMP_EXTENDED_VISIBILITY,
    deps = [
        ":logging",
        ":util",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
    ],
)

cc_library(
    name = "binary_info",
    hdrs = [
        "binary_info.h",
    ],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        ":call_graph",
        ":control_flow",
    ],
)

cc_library(
    name = "centipede_callbacks",
    srcs = [
        "centipede_callbacks.cc",
    ],
    hdrs = [
        "centipede_callbacks.h",
    ],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        ":binary_info",
        ":byte_array_mutator",
        ":call_graph",
        ":command",
        ":control_flow",
        ":defs",
        ":environment",
        ":execution_request",
        ":execution_result",
        ":fuzztest_mutator",
        ":knobs",
        ":logging",
        ":shared_memory_blob_sequence",
        ":util",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "shard_reader",
    srcs = ["shard_reader.cc"],
    hdrs = ["shard_reader.h"],
    # TODO(kcc): move shard_reader test from testing/centipede_test.cc into a dedicated test.
    deps = [
        ":blob_file",
        ":defs",
        ":feature",
        ":util",
        "@com_google_absl//absl/container:flat_hash_map",
    ],
)

cc_library(
    name = "centipede_lib",
    srcs = [
        "centipede.cc",
    ],
    hdrs = [
        "centipede.h",
    ],
    deps = [
        ":blob_file",
        ":centipede_callbacks",
        ":command",
        ":control_flow",
        ":corpus",
        ":coverage",
        ":defs",
        ":environment",
        ":execution_result",
        ":feature",
        ":feature_set",
        ":logging",
        ":remote_file",
        ":rusage_profiler",
        ":rusage_stats",
        ":shard_reader",
        ":stats",
        ":util",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "centipede_interface",
    srcs = [
        "centipede_interface.cc",
    ],
    hdrs = [
        "centipede_interface.h",
    ],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        ":analyze_corpora",
        ":binary_info",
        ":blob_file",
        ":centipede_callbacks",
        ":centipede_lib",
        ":command",
        ":coverage",
        ":defs",
        ":environment",
        ":logging",
        ":minimize_crash",
        ":remote_file",
        ":shard_reader",
        ":stats",
        ":util",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "environment",
    srcs = [
        "environment.cc",
    ],
    hdrs = [
        "environment.h",
    ],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        ":knobs",
        ":logging",
        ":remote_file",
        ":util",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
    ],
)

cc_library(
    name = "centipede_default_callbacks",
    srcs = ["centipede_default_callbacks.cc"],
    hdrs = ["centipede_default_callbacks.h"],
    deps = [
        ":centipede_interface",
        ":defs",
        ":environment",
        ":execution_result",
        ":logging",
    ],
)

cc_library(
    name = "fuzztest_mutator",
    srcs = ["fuzztest_mutator.cc"],
    hdrs = ["fuzztest_mutator.h"],
    deps = [
        ":defs",
        "@com_google_absl//absl/random",
        "@com_google_fuzztest//fuzztest:domain_core",
    ],
)

cc_library(
    name = "weak_sancov_stubs",
    srcs = ["weak_sancov_stubs.cc"],
    alwayslink = 1,
)

# runner_fork_server can be linked to a binary or used directly as a .so via LD_PRELOAD.
cc_library(
    name = "runner_fork_server",
    srcs = ["runner_fork_server.cc"],
    visibility = PUBLIC_API_VISIBILITY,
    alwayslink = 1,  # Otherwise the linker drops the fork server.
)

cc_library(
    name = "runner_cmp_trace",
    hdrs = ["runner_cmp_trace.h"],
)

# The runner library is special:
#   * It must not be instrumented with asan, sancov, etc.
#   * It must not have heavy dependencies, and ideally not at all.
#     Exceptions are STL and absl::span (temporarily, until we can switch to
#     std::span).
#   * The bazel rule :centipede_runner must produce a self-contained .a file
#     with all
#     objects in it, which means the build rule must not depend other .a rules.
#
#  Some of the .cc and .h files used by the runner are also used by the engine,
#  e.g. feature.cc. These files are compiled by the engine and the runner
#  separately, with different compiler flags.
RUNNER_SOURCES_NO_MAIN = [
    "byte_array_mutator.cc",
    "byte_array_mutator.h",
    "callstack.h",
    "concurrent_bitset.h",
    "concurrent_byteset.h",
    "defs.h",
    "execution_request.cc",
    "execution_request.h",
    "execution_result.cc",
    "execution_result.h",
    "feature.cc",
    "feature.h",
    "foreach_nonzero.h",
    "hashed_ring_buffer.h",
    "int_utils.h",
    "knobs.h",
    "knobs.cc",
    "pc_info.h",
    "reverse_pc_table.h",
    "rolling_hash.h",
    "runner.cc",
    "runner.h",
    "runner_dl_info.h",
    "runner_dl_info.cc",
    "runner_utils.h",
    "runner_utils.cc",
    "runner_cmp_trace.h",
    "runner_fork_server.cc",
    "runner_interceptors.cc",
    "runner_interface.h",
    "runner_sancov.cc",
    "shared_memory_blob_sequence.cc",
    "shared_memory_blob_sequence.h",
]

RUNNER_SOURCES_WITH_MAIN = RUNNER_SOURCES_NO_MAIN + ["runner_main.cc"]

# TODO(kcc): ensure asan/tsan/msan/ubsan instrumentation is disabled for runner.
RUNNER_COPTS = ["-fsanitize-coverage=0"]

RUNNER_LINKOPTS = [
    "-ldl",  # for dlsym
    "-lrt",  # for shm_open
    "-lpthread",  # for pthread_once
]

# WARNING: be careful with more deps here. Use only the most trivial ones.
RUNNER_DEPS = [
    "@com_google_absl//absl/types:span",
    "@com_google_absl//absl/base:core_headers",
]

# A fuzz target needs to link with this library in order to run with Centipede.
# The fuzz target must provide its own main().
#
# See also comments above RUNNER_SOURCES_NO_MAIN.
#
cc_library(
    name = "centipede_runner_no_main",
    srcs = RUNNER_SOURCES_NO_MAIN,
    copts = RUNNER_COPTS,
    linkopts = RUNNER_LINKOPTS,
    visibility = ["//visibility:public"],
    deps = RUNNER_DEPS,
)

# Same as :centipede_runner_no_main but as a DSO. Experimental.
cc_binary(
    name = "centipede_runner_no_main.so",
    srcs = RUNNER_SOURCES_NO_MAIN,
    copts = RUNNER_COPTS,
    linkopts = RUNNER_LINKOPTS,
    linkshared = 1,
    visibility = ["//visibility:public"],
    deps = RUNNER_DEPS,
)

# A full self-contained library archive that external clients should link to
# their fuzz targets to make them compatible with the Centipede fuzzing engine
# (the `:centipede` target in this BUILD).
cc_library(
    name = "centipede_runner",
    srcs = RUNNER_SOURCES_WITH_MAIN,
    copts = RUNNER_COPTS,
    linkopts = RUNNER_LINKOPTS,
    visibility = ["//visibility:public"],
    deps = RUNNER_DEPS,
)

################################################################################
#                        General-purpose testing utilities
################################################################################

cc_library(
    name = "test_util",
    srcs = ["test_util.cc"],
    hdrs = ["test_util.h"],
    deps = [
        ":defs",
        ":logging",
        ":util",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

sh_library(
    name = "test_util_sh",
    srcs = ["test_util.sh"],
    data = [
    ],
)

################################################################################
#                               Unit tests
################################################################################

cc_test(
    name = "environment_test",
    srcs = ["environment_test.cc"],
    deps = [
        ":environment",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "rolling_hash_test",
    srcs = ["rolling_hash_test.cc"],
    deps = [
        ":feature",
        ":rolling_hash",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "logging_test",
    srcs = ["logging_test.cc"],
    deps = [
        ":logging",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/log:scoped_mock_log",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "util_test",
    srcs = ["util_test.cc"],
    copts = ["-fno-signed-char"],
    deps = [
        ":defs",
        ":logging",
        ":test_util",
        ":util",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "config_util_test",
    srcs = ["config_util_test.cc"],
    deps = [
        # Include this just to get some flags external to the test itself.
        ":environment",  # buildcleaner:keep
        ":config_util",
        ":logging",
        "@com_google_googletest//:gtest_main",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "config_file_test",
    srcs = ["config_file_test.cc"],
    deps = [
        ":config_file",
        "@com_google_googletest//:gtest_main",
        # Defines FLAGS_flagfile.
        "@com_google_absl//absl/flags:parse",  # buildcleaner:keep
    ],
)

cc_test(
    name = "rusage_stats_test",
    size = "medium",
    timeout = "long",
    srcs = ["rusage_stats_test.cc"],
    deps = [
        ":logging",
        ":rusage_stats",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/functional:any_invocable",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "rusage_profiler_test",
    # Allocates large blocks of memory to fight small number volatility.
    size = "large",
    timeout = "long",
    srcs = ["rusage_profiler_test.cc"],
    deps = [
        ":rusage_profiler",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "stats_test",
    srcs = ["stats_test.cc"],
    deps = [
        ":logging",
        ":stats",
        ":test_util",
        ":util",
        "@com_google_absl//absl/log:log_sink",
        "@com_google_absl//absl/log:log_sink_registry",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "minimize_crash_test",
    srcs = ["minimize_crash_test.cc"],
    deps = [
        ":defs",
        ":minimize_crash",
        ":test_util",
        ":util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "analyze_corpora_test",
    srcs = ["analyze_corpora_test.cc"],
    deps = [
        ":analyze_corpora",
        ":logging",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "blob_file_test",
    srcs = ["blob_file_test.cc"],
    deps = [
        ":blob_file",
        ":test_util",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "shared_memory_blob_sequence_test",
    srcs = ["shared_memory_blob_sequence_test.cc"],
    deps = [
        ":shared_memory_blob_sequence",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "execution_result_test",
    srcs = ["execution_result_test.cc"],
    deps = [
        ":execution_result",
        ":feature",
        ":shared_memory_blob_sequence",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "byte_array_mutator_test",
    srcs = ["byte_array_mutator_test.cc"],
    deps = [
        ":byte_array_mutator",
        ":defs",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "feature_test",
    srcs = ["feature_test.cc"],
    deps = [
        ":feature",
        ":logging",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "foreach_nonzero_test",
    srcs = ["foreach_nonzero_test.cc"],
    deps = [
        ":foreach_nonzero",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "fuzztest_mutator_test",
    srcs = ["fuzztest_mutator_test.cc"],
    deps = [
        ":defs",
        ":fuzztest_mutator",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "knobs_test",
    srcs = ["knobs_test.cc"],
    deps = [
        ":knobs",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "reverse_pc_table_test",
    srcs = ["reverse_pc_table_test.cc"],
    deps = [
        ":pc_info",
        ":reverse_pc_table",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "callstack_test",
    srcs = ["callstack_test.cc"],
    tags = ["not_run:arm"],
    deps = [
        ":callstack",
        ":defs",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "feature_set_test",
    srcs = ["feature_set_test.cc"],
    deps = [
        ":feature",
        ":feature_set",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "corpus_test",
    srcs = ["corpus_test.cc"],
    deps = [
        ":control_flow",
        ":corpus",
        ":defs",
        ":feature",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_binary(
    name = "command_test_helper",
    srcs = ["command_test_helper.cc"],
    deps = [":runner_fork_server"],
)

cc_test(
    name = "command_test",
    srcs = ["command_test.cc"],
    data = [":command_test_helper"],
    deps = [
        ":command",
        ":logging",
        ":test_util",
        ":util",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "runner_cmp_trace_test",
    srcs = ["runner_cmp_trace_test.cc"],
    deps = [
        ":runner_cmp_trace",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "control_flow_test",
    srcs = ["control_flow_test.cc"],
    data = [
        "@com_google_fuzztest//centipede/testing:test_fuzz_target",
        "@com_google_fuzztest//centipede/testing:test_fuzz_target_trace_pc",
        "@com_google_fuzztest//centipede/testing:threaded_fuzz_target",
    ],
    tags = ["not_run:arm"],
    deps = [
        ":control_flow",
        ":defs",
        ":logging",
        ":test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "call_graph_test",
    srcs = ["call_graph_test.cc"],
    deps = [
        ":call_graph",
        ":logging",
        "@com_google_googletest//:gtest_main",
    ],
)

################################################################################
#                               Other tests
################################################################################

# Verify that the `:centipede` target indeed creates a binary with the
# expected name.
sh_test(
    name = "centipede_binary_test",
    srcs = ["centipede_binary_test.sh"],
    data = [
        ":centipede",
        ":test_util_sh",
    ],
)
