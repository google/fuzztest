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

load("@rules_proto//proto:defs.bzl", "proto_library")
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
        ":centipede_callbacks",
        ":centipede_default_callbacks",
        ":centipede_interface",
        ":config_file",
        ":environment_flags",
        "@com_google_absl//absl/log:flags",
    ],
)

cc_uninstrumented_binary(
    name = "centipede_uninstrumented",
    binary = ":centipede",
    visibility = PUBLIC_API_VISIBILITY,
)

# A standalone seed corpus generator.
cc_binary(
    name = "seed_corpus_maker",
    srcs = ["seed_corpus_maker.cc"],
    deps = [
        ":config_init",
        ":seed_corpus_maker_flags",
        ":seed_corpus_maker_lib",
        "@com_google_absl//absl/flags:flag",
    ],
)

###############################################################################
#                              Proto libraries
###############################################################################

# Configuration for the seed corpus maker.
proto_library(
    name = "seed_corpus_config_proto",
    srcs = ["seed_corpus_config.proto"],
)

cc_proto_library(
    name = "seed_corpus_config_cc_proto",
    deps = [":seed_corpus_config_proto"],
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
    name = "symbol_table",
    srcs = ["symbol_table.cc"],
    hdrs = ["symbol_table.h"],
    visibility = TEMP_EXTENDED_VISIBILITY,
    deps = [
        ":command",
        ":control_flow",
        ":logging",
        ":pc_info",
        ":util",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
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
    srcs = ["pc_info.cc"],
    hdrs = ["pc_info.h"],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        ":defs",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/types:span",
    ],
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
    visibility = TEMP_EXTENDED_VISIBILITY,
    deps = [
        "@com_google_absl//absl/flags:reflection",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "config_init",
    srcs = ["config_init.cc"],
    hdrs = ["config_init.h"],
    visibility = TEMP_EXTENDED_VISIBILITY,
    deps = [
        ":config_util",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/base:log_severity",
        "@com_google_absl//absl/flags:config",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log:globals",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "config_file",
    srcs = ["config_file.cc"],
    hdrs = ["config_file.h"],
    visibility = TEMP_EXTENDED_VISIBILITY,
    deps = [
        ":config_init",
        ":config_util",
        ":logging",
        ":remote_file",
        ":util",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/flags:reflection",
        "@com_google_absl//absl/log",
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
        ":workdir",
        "@com_google_absl//absl/container:btree",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
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
        ":mutation_input",
        ":runner_result",
        ":util",
        ":workdir",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
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
        ":coverage",
        ":defs",
        ":feature",
        ":logging",
        ":remote_file",
        ":shard_reader",
        ":workdir",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
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
    name = "execution_metadata",
    srcs = ["execution_metadata.cc"],
    hdrs = ["execution_metadata.h"],
    deps = [
        # This target must have a minimal set of dependencies since it is
        # used in centipede_runner.
        ":defs",
        ":shared_memory_blob_sequence",
    ],
)

cc_library(
    name = "runner_result",
    srcs = ["runner_result.cc"],
    hdrs = ["runner_result.h"],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        # This target must have a minimal set of dependencies since it is
        # used in centipede_runner.
        ":feature",
        ":execution_metadata",
        ":runner_cmp_trace",
        ":shared_memory_blob_sequence",
    ],
)

cc_library(
    name = "runner_request",
    srcs = ["runner_request.cc"],
    hdrs = ["runner_request.h"],
    deps = [
        # This target must have a minimal set of dependencies since it is
        # used in centipede_runner.
        ":shared_memory_blob_sequence",
        ":execution_metadata",
        ":mutation_input",
        ":defs",
    ],
)

cc_library(
    name = "mutation_input",
    hdrs = ["mutation_input.h"],
    deps = [
        # This target must have a minimal set of dependencies since it is
        # used in centipede_runner.
        ":defs",
        ":execution_metadata",
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
        ":execution_metadata",
        ":knobs",
        ":mutation_input",
    ],
)

# Library for dealing with code coverage data from
# https://clang.llvm.org/docs/SanitizerCoverage.html.
cc_library(
    name = "coverage",
    srcs = [
        "coverage.cc",
    ],
    hdrs = [
        "coverage.h",
    ],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        ":control_flow",
        ":defs",
        ":feature",
        ":logging",
        ":symbol_table",
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
    ],
    hdrs = [
        "control_flow.h",
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
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
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
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
    ],
)

cc_library(
    name = "feature_set",
    srcs = ["feature_set.cc"],
    hdrs = ["feature_set.h"],
    deps = [
        ":control_flow",
        ":feature",
        ":logging",
        ":util",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
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
        ":execution_metadata",
        ":feature",
        ":feature_set",
        ":logging",
        ":util",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
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
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
    ],
)

cc_library(
    name = "binary_info",
    srcs = ["binary_info.cc"],
    hdrs = [
        "binary_info.h",
    ],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        ":call_graph",
        ":command",
        ":control_flow",
        ":pc_info",
        ":remote_file",
        ":symbol_table",
        ":util",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
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
        ":fuzztest_mutator",
        ":knobs",
        ":logging",
        ":mutation_input",
        ":runner_request",
        ":runner_result",
        ":shared_memory_blob_sequence",
        ":symbol_table",
        ":util",
        ":workdir",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
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
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "environment_flags",
    srcs = ["environment_flags.cc"],
    hdrs = ["environment_flags.h"],
    visibility = PUBLIC_API_VISIBILITY,
    deps = [
        ":environment",
        ":logging",
        ":util",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
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
        ":binary_info",
        ":blob_file",
        ":centipede_callbacks",
        ":command",
        ":control_flow",
        ":corpus",
        ":coverage",
        ":defs",
        ":environment",
        ":feature",
        ":feature_set",
        ":logging",
        ":mutation_input",
        ":pc_info",
        ":remote_file",
        ":runner_result",
        ":rusage_profiler",
        ":rusage_stats",
        ":shard_reader",
        ":stats",
        ":symbol_table",
        ":util",
        ":workdir",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
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
        ":corpus",
        ":coverage",
        ":defs",
        ":distill",
        ":environment",
        ":feature",
        ":logging",
        ":minimize_crash",
        ":pc_info",
        ":remote_file",
        ":shard_reader",
        ":stats",
        ":util",
        ":workdir",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
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
        ":defs",
        ":feature",
        ":knobs",
        ":logging",
        ":remote_file",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
    ],
)

cc_library(
    name = "distill",
    srcs = ["distill.cc"],
    hdrs = ["distill.h"],
    deps = [
        ":blob_file",
        ":defs",
        ":environment",
        ":feature",
        ":feature_set",
        ":logging",
        ":shard_reader",
        ":util",
        ":workdir",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "centipede_default_callbacks",
    srcs = ["centipede_default_callbacks.cc"],
    hdrs = ["centipede_default_callbacks.h"],
    deps = [
        ":centipede_callbacks",
        ":centipede_interface",
        ":defs",
        ":environment",
        ":logging",
        ":mutation_input",
        ":runner_result",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
    ],
)

cc_library(
    name = "fuzztest_mutator",
    srcs = ["fuzztest_mutator.cc"],
    hdrs = ["fuzztest_mutator.h"],
    deps = [
        ":defs",
        ":execution_metadata",
        ":mutation_input",
        "@com_google_absl//absl/random",
        "@com_google_fuzztest//fuzztest:domain_core",
    ],
)

cc_library(
    name = "weak_sancov_stubs",
    srcs = ["weak_sancov_stubs.cc"],
    visibility = PUBLIC_API_VISIBILITY,
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

# Library for manipulating centipede runner flags. This is not used by the
# runner itself but by other tools.
cc_library(
    name = "runner_flags",
    srcs = ["runner_flags.cc"],
    hdrs = ["runner_flags.h"],
    visibility = PUBLIC_API_VISIBILITY,
    # This has no dependency and only uses string, pair and vector.
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
    "execution_metadata.cc",
    "execution_metadata.h",
    "runner_request.cc",
    "runner_request.h",
    "runner_result.cc",
    "runner_result.h",
    "feature.cc",
    "feature.h",
    "foreach_nonzero.h",
    "hashed_ring_buffer.h",
    "int_utils.h",
    "knobs.h",
    "knobs.cc",
    "mutation_input.h",
    "pc_info.h",
    "reverse_pc_table.h",
    "rolling_hash.h",
    "runner.cc",
    "runner.h",
    "runner_dl_info.h",
    "runner_dl_info.cc",
    "runner_sancov_object.h",
    "runner_sancov_object.cc",
    "runner_utils.h",
    "runner_utils.cc",
    "runner_cmp_trace.h",
    "runner_fork_server.cc",
    "runner_interceptors.cc",
    "runner_interface.h",
    "runner_sancov.cc",
    "runner_sanitizer.cc",
    "shared_memory_blob_sequence.cc",
    "shared_memory_blob_sequence.h",
]

RUNNER_SOURCES_WITH_MAIN = RUNNER_SOURCES_NO_MAIN + ["runner_main.cc"]

# Disable sancov and sanitizer instrumentation
RUNNER_COPTS = [
    "-fsanitize-coverage=0",
    "-fno-sanitize=address,hwaddress,memory,thread,undefined",
]

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
    hdrs = ["runner_interface.h"],
    copts = RUNNER_COPTS,
    linkopts = RUNNER_LINKOPTS,
    linkstatic = True,  # Must be linked statically even when dynamic_mode=on.
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
    linkstatic = True,  # Must be linked statically even when dynamic_mode=on.
    visibility = ["//visibility:public"],
    deps = RUNNER_DEPS,
)

# Utilities for seed corpus generation.
cc_library(
    name = "seed_corpus_maker_lib",
    srcs = ["seed_corpus_maker_lib.cc"],
    hdrs = ["seed_corpus_maker_lib.h"],
    deps = [
        ":blob_file",
        ":defs",
        ":logging",
        ":remote_file",
        ":seed_corpus_config_cc_proto",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:span",
        "@com_google_protobuf//:protobuf",
    ],
)

# Flags for :seed_corpus_maker.
cc_library(
    name = "seed_corpus_maker_flags",
    srcs = ["seed_corpus_maker_flags.cc"],
    hdrs = ["seed_corpus_maker_flags.h"],
    deps = ["@com_google_absl//absl/flags:flag"],
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

cc_library(
    name = "workdir",
    srcs = ["workdir.cc"],
    hdrs = ["workdir.h"],
    deps = [
        ":environment",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

sh_library(
    name = "test_fuzzing_util_sh",
    srcs = ["test_fuzzing_util.sh"],
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
    name = "binary_info_test",
    srcs = ["binary_info_test.cc"],
    deps = [
        ":binary_info",
        ":pc_info",
        ":symbol_table",
        ":test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "environment_test",
    srcs = ["environment_test.cc"],
    deps = [
        ":environment",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "workdir_test",
    srcs = ["workdir_test.cc"],
    deps = [
        ":environment",
        ":workdir",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "pc_info_test",
    srcs = ["pc_info_test.cc"],
    deps = [
        ":pc_info",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "remote_file_test",
    srcs = ["remote_file_test.cc"],
    deps = [
        ":remote_file",
        ":test_util",
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
    name = "symbol_table_test",
    srcs = ["symbol_table_test.cc"],
    deps = [
        ":symbol_table",
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
        ":feature",
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
        ":environment_flags",
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
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "distill_test",
    srcs = ["distill_test.cc"],
    deps = [
        ":blob_file",
        ":defs",
        ":distill",
        ":environment",
        ":feature",
        ":shard_reader",
        ":test_util",
        ":util",
        ":workdir",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:reflection",
        "@com_google_absl//absl/log:check",
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
        ":rusage_stats",
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
        ":environment",
        ":stats",
        ":test_util",
        ":util",
        "@com_google_absl//absl/log:log_entry",
        "@com_google_absl//absl/log:log_sink",
        "@com_google_absl//absl/log:log_sink_registry",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "minimize_crash_test",
    srcs = ["minimize_crash_test.cc"],
    deps = [
        ":centipede_callbacks",
        ":defs",
        ":environment",
        ":minimize_crash",
        ":runner_result",
        ":test_util",
        ":util",
        ":workdir",
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
    name = "execution_metadata_test",
    srcs = ["execution_metadata_test.cc"],
    deps = [
        ":execution_metadata",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "runner_result_test",
    srcs = ["runner_result_test.cc"],
    deps = [
        ":feature",
        ":runner_result",
        ":shared_memory_blob_sequence",
        ":test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "mutation_input_test",
    srcs = ["mutation_input_test.cc"],
    deps = [
        ":mutation_input",
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
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
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
        ":feature_set",
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
        ":binary_info",
        ":control_flow",
        ":defs",
        ":logging",
        ":symbol_table",
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

cc_test(
    name = "runner_flags_test",
    srcs = ["runner_flags_test.cc"],
    deps = [
        ":runner_flags",
        "@com_google_googletest//:gtest_main",
    ],
)

################################################################################
#                               Other tests
################################################################################

cc_test(
    name = "centipede_test",
    timeout = "long",
    srcs = ["centipede_test.cc"],
    data = [
        "@com_google_fuzztest//centipede/testing:abort_fuzz_target",
        "@com_google_fuzztest//centipede/testing:seeded_fuzz_target",
        "@com_google_fuzztest//centipede/testing:test_fuzz_target",
        "@com_google_fuzztest//centipede/testing:test_input_filter",
    ],
    tags = ["not_run:arm"],
    deps = [
        ":blob_file",
        ":centipede_callbacks",
        ":centipede_default_callbacks",
        ":centipede_interface",
        ":corpus",
        ":defs",
        ":environment",
        ":feature",
        ":logging",
        ":runner_result",
        ":shard_reader",
        ":test_util",
        ":util",
        ":workdir",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

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

cc_test(
    name = "coverage_test",
    srcs = ["coverage_test.cc"],
    data = [
        "@com_google_fuzztest//centipede/testing:test_fuzz_target",
        "@com_google_fuzztest//centipede/testing:test_fuzz_target_trace_pc",
        "@com_google_fuzztest//centipede/testing:threaded_fuzz_target",
    ],
    tags = ["not_run:arm"],
    deps = [
        ":binary_info",
        ":centipede_interface",
        ":control_flow",
        ":coverage",
        ":defs",
        ":environment",
        ":feature",
        ":logging",
        ":pc_info",
        ":runner_result",
        ":symbol_table",
        ":test_util",
        ":util",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)
