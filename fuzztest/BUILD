# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# FuzzTest: a coverage-guided fuzzing / property-based testing framework.

load("@bazel_skylib//rules:common_settings.bzl", "bool_flag")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

exports_files(["LICENSE"])

################################################################################
# Flag and setting to enable the Centipede integration.
################################################################################
bool_flag(
    name = "centipede_integration",
    build_setting_default = False,
)

config_setting(
    name = "use_centipede",
    flag_values = {":centipede_integration": "True"},
)
################################################################################

################################################################################
# Flag and setting to enable use of Riegeli
################################################################################
bool_flag(
    name = "use_riegeli",
    build_setting_default = True,
)

config_setting(
    name = "disable_riegeli",
    flag_values = {":use_riegeli": "False"},
)
################################################################################

cc_library(
    name = "fuzztest",
    hdrs = ["fuzztest.h"],
    deps = [
        ":domain",
        ":fuzztest_macros",
    ],
)

cc_library(
    name = "fuzztest_core",
    hdrs = ["fuzztest_core.h"],
    deps = [
        ":domain_core",
        ":fuzztest_macros",
    ],
)

cc_library(
    name = "fuzztest_macros",
    srcs = ["fuzztest_macros.cc"],
    hdrs = [
        "fuzztest_macros.h",
    ],
    deps = [
        ":io",
        ":logging",
        ":registration",
        ":registry",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/strings:string_view",
    ],
)

cc_test(
    name = "fuzztest_macros_test",
    srcs = ["fuzztest_macros_test.cc"],
    deps = [
        ":fuzztest_macros",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@com_google_fuzztest//common:temp_dir",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "fuzztest_gtest_main",
    testonly = 1,
    srcs = ["fuzztest_gtest_main.cc"],
    deps = [
        "@abseil-cpp//absl/strings",
        "@com_google_fuzztest//fuzztest:init_fuzztest",
        "@googletest//:gtest",
    ],
)

cc_library(
    name = "init_fuzztest",
    testonly = 1,
    srcs = ["init_fuzztest.cc"],
    hdrs = ["init_fuzztest.h"],
    deps = [
        ":configuration",
        ":flag_name",
        ":googletest_adaptor",
        ":io",
        ":logging",
        ":registry",
        ":runtime",
        "@abseil-cpp//absl/algorithm:container",
        "@abseil-cpp//absl/base:no_destructor",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/flags:reflection",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/time",
        "@googletest//:gtest",
    ],
    alwayslink = True,
)

# TODO(hadi88): Add an e2e test for llvm_fuzzer_wrapper.
cc_library(
    name = "llvm_fuzzer_main",
    testonly = True,
    srcs = ["llvm_fuzzer_main.cc"],
    deps = [
        ":init_fuzztest",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/flags:parse",
        "@googletest//:gtest",
    ],
    alwayslink = True,
)

cc_library(
    name = "llvm_fuzzer_wrapper",
    testonly = True,
    srcs = ["llvm_fuzzer_wrapper.cc"],
    deps = [
        ":domain_core",
        ":fuzztest",
        ":fuzztest_macros",
        ":io",
        ":logging",
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/base:no_destructor",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/random:bit_gen_ref",
        "@abseil-cpp//absl/synchronization",
    ],
    alwayslink = True,
)

################################################################################
# Internal
################################################################################

# TODO(lszekeres): Move these to internal/BUILD.

cc_library(
    name = "absl_helpers",
    hdrs = ["internal/domains/absl_helpers.h"],
    deps = [
        ":logging",
        "@abseil-cpp//absl/time",
    ],
)

cc_library(
    name = "any",
    hdrs = ["internal/any.h"],
    deps = [
        ":logging",
        ":meta",
    ],
)

cc_test(
    name = "any_test",
    srcs = ["internal/any_test.cc"],
    deps = [
        ":any",
        "@abseil-cpp//absl/strings",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "centipede_adaptor",
    srcs = ["internal/centipede_adaptor.cc"],
    hdrs = ["internal/centipede_adaptor.h"],
    defines = ["FUZZTEST_USE_CENTIPEDE"],
    deps = [
        ":any",
        ":configuration",
        ":domain_core",
        ":fixture_driver",
        ":flag_name",
        ":logging",
        ":runtime",
        ":table_of_recent_compares",
        "@abseil-cpp//absl/algorithm:container",
        "@abseil-cpp//absl/base:no_destructor",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/memory",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/random:distributions",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/time",
        "@abseil-cpp//absl/types:span",
        "@com_google_fuzztest//centipede:centipede_callbacks",
        "@com_google_fuzztest//centipede:centipede_default_callbacks",
        "@com_google_fuzztest//centipede:centipede_interface",
        "@com_google_fuzztest//centipede:centipede_runner_no_main",
        "@com_google_fuzztest//centipede:environment",
        "@com_google_fuzztest//centipede:execution_metadata",
        "@com_google_fuzztest//centipede:mutation_input",
        "@com_google_fuzztest//centipede:runner_result",
        "@com_google_fuzztest//centipede:workdir",
        "@com_google_fuzztest//common:defs",
        "@com_google_fuzztest//common:temp_dir",
    ],
)

cc_library(
    name = "compatibility_mode",
    srcs = ["internal/compatibility_mode.cc"],
    hdrs = ["internal/compatibility_mode.h"],
    deps = [
        ":domain_core",
        ":fixture_driver",
        ":logging",
        ":runtime",
        "@abseil-cpp//absl/random:distributions",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/time",
    ] + select({
        "//conditions:default": [],
    }),
)

cc_library(
    name = "configuration",
    srcs = ["internal/configuration.cc"],
    hdrs = ["internal/configuration.h"],
    deps = [
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/time",
    ],
)

cc_test(
    name = "configuration_test",
    srcs = ["internal/configuration_test.cc"],
    deps = [
        ":configuration",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/time",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "corpus_database",
    srcs = ["internal/corpus_database.cc"],
    hdrs = ["internal/corpus_database.h"],
    deps = [
        ":configuration",
        ":io",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/time",
    ],
)

cc_library(
    name = "coverage",
    srcs = ["internal/coverage.cc"],
    hdrs = ["internal/coverage.h"],
    defines = select({
        "@com_google_fuzztest//fuzztest:use_centipede": ["FUZZTEST_USE_CENTIPEDE"],
        "//conditions:default": [],
    }),
    deps = [
        ":domain_core",
        ":flag_name",
        ":logging",
        ":table_of_recent_compares",
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_library(
    name = "domain",
    srcs = ["internal/domains/in_grammar_impl.cc"],
    hdrs = [
        "domain.h",
        "internal/domains/in_grammar_impl.h",
        "internal/domains/in_regexp_impl.h",
        "internal/domains/protobuf_domain_impl.h",
    ],
    # Public for cc_fuzztest_grammar_library rule.
    visibility = ["//visibility:public"],
    deps = [
        ":any",
        ":domain_core",
        ":logging",
        ":meta",
        ":regexp_dfa",
        ":serialization",
        ":status",
        ":type_support",
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/base:no_destructor",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/random:bit_gen_ref",
        "@abseil-cpp//absl/random:distributions",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/synchronization",
        "@abseil-cpp//absl/types:span",
    ],
)

# The core domain library without external dependencies e.g. re2. Mainly used
# by the default Centipede mutation.
cc_library(
    name = "domain_core",
    srcs = ["internal/domains/domain_base.cc"],
    hdrs = [
        "domain_core.h",
        "internal/domains/aggregate_of_impl.h",
        "internal/domains/arbitrary_impl.h",
        "internal/domains/bit_flag_combination_of_impl.h",
        "internal/domains/container_mutation_helpers.h",
        "internal/domains/container_of_impl.h",
        "internal/domains/domain.h",
        "internal/domains/domain_base.h",
        "internal/domains/domain_type_erasure.h",
        "internal/domains/element_of_impl.h",
        "internal/domains/filter_impl.h",
        "internal/domains/flat_map_impl.h",
        "internal/domains/in_range_impl.h",
        "internal/domains/map_impl.h",
        "internal/domains/mutation_metadata.h",
        "internal/domains/one_of_impl.h",
        "internal/domains/optional_of_impl.h",
        "internal/domains/overlap_of_impl.h",
        "internal/domains/serialization_helpers.h",
        "internal/domains/smart_pointer_of_impl.h",
        "internal/domains/special_values.h",
        "internal/domains/unique_elements_container_of_impl.h",
        "internal/domains/value_mutation_helpers.h",
        "internal/domains/variant_of_impl.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":absl_helpers",
        ":any",
        ":logging",
        ":meta",
        ":printer",
        ":seed_seq",
        ":serialization",
        ":status",
        ":table_of_recent_compares",
        ":type_support",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/functional:function_ref",
        "@abseil-cpp//absl/numeric:bits",
        "@abseil-cpp//absl/numeric:int128",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/random:bit_gen_ref",
        "@abseil-cpp//absl/random:distributions",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/time",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_library(
    name = "fixture_driver",
    srcs = ["internal/fixture_driver.cc"],
    hdrs = ["internal/fixture_driver.h"],
    deps = [
        ":any",
        ":domain_core",
        ":logging",
        ":meta",
        ":printer",
        ":registration",
        ":type_support",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_test(
    name = "fixture_driver_test",
    size = "small",
    srcs = ["internal/fixture_driver_test.cc"],
    deps = [
        ":any",
        ":domain_core",
        ":fixture_driver",
        ":logging",
        ":registration",
        "@abseil-cpp//absl/types:span",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "flag_name",
    hdrs = ["internal/flag_name.h"],
)

cc_library(
    name = "googletest_adaptor",
    testonly = True,
    srcs = ["internal/googletest_adaptor.cc"],
    hdrs = ["internal/googletest_adaptor.h"],
    deps = [
        ":configuration",
        ":corpus_database",
        ":flag_name",
        ":io",
        ":registry",
        ":runtime",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/strings:string_view",
        "@googletest//:gtest",
    ],
)

cc_library(
    name = "googletest_fixture_adapter",
    testonly = True,
    hdrs = ["googletest_fixture_adapter.h"],
    deps = [
        ":fixture_driver",
        "@googletest//:gtest",
    ],
)

cc_library(
    name = "io",
    srcs = ["internal/io.cc"],
    hdrs = ["internal/io.h"],
    deps = [
        ":logging",
        "@abseil-cpp//absl/functional:function_ref",
        "@abseil-cpp//absl/hash",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/time",
        "@abseil-cpp//absl/types:span",
        "@com_google_fuzztest//common:blob_file",
        "@com_google_fuzztest//common:defs",
        "@com_google_fuzztest//common:remote_file",
    ] + select({
        "//conditions:default": [],
    }),
)

cc_test(
    name = "io_test",
    srcs = ["internal/io_test.cc"],
    deps = [
        ":fuzztest_core",
        ":io",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
        "@com_google_fuzztest//common:blob_file",
        "@com_google_fuzztest//common:defs",
        "@com_google_fuzztest//common:temp_dir",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "logging",
    srcs = ["internal/logging.cc"],
    hdrs = ["internal/logging.h"],
    deps = [
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/synchronization",
    ],
)

cc_library(
    name = "meta",
    hdrs = ["internal/meta.h"],
    deps = ["@abseil-cpp//absl/numeric:int128"],
)

cc_library(
    name = "printer",
    hdrs = ["internal/printer.h"],
    deps = [
        ":meta",
        "@abseil-cpp//absl/strings:str_format",
    ],
)

cc_library(
    name = "regexp_dfa",
    srcs = ["internal/domains/regexp_dfa.cc"],
    hdrs = ["internal/domains/regexp_dfa.h"],
    deps = [
        ":logging",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/random:bit_gen_ref",
        "@abseil-cpp//absl/random:distributions",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:string_view",
        "@re2",
    ],
)

cc_library(
    name = "registration",
    hdrs = ["internal/registration.h"],
    deps = [
        ":domain_core",
        ":meta",
        ":printer",
        ":type_support",
        "@abseil-cpp//absl/functional:any_invocable",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_library(
    name = "registry",
    srcs = ["internal/registry.cc"],
    hdrs = ["internal/registry.h"],
    deps = [
        ":compatibility_mode",
        ":fixture_driver",
        ":registration",
        ":runtime",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/functional:function_ref",
        "@abseil-cpp//absl/strings:string_view",
    ] + select({
        "@com_google_fuzztest//fuzztest:use_centipede": [":centipede_adaptor"],
        "//conditions:default": [],
    }),
)

cc_library(
    name = "runtime",
    srcs = ["internal/runtime.cc"],
    hdrs = ["internal/runtime.h"],
    deps = [
        ":configuration",
        ":corpus_database",
        ":coverage",
        ":domain_core",
        ":fixture_driver",
        ":flag_name",
        ":io",
        ":logging",
        ":printer",
        ":registration",
        ":seed_seq",
        ":serialization",
        ":status",
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/functional:any_invocable",
        "@abseil-cpp//absl/functional:bind_front",
        "@abseil-cpp//absl/functional:function_ref",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/random:bit_gen_ref",
        "@abseil-cpp//absl/random:distributions",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/time",
        "@abseil-cpp//absl/types:span",
        "@com_google_fuzztest//common:bazel",
    ],
)

cc_test(
    name = "runtime_test",
    srcs = ["internal/runtime_test.cc"],
    deps = [
        ":configuration",
        ":domain_core",
        ":flag_name",
        ":runtime",
        ":test_protobuf_cc_proto",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "seed_seq",
    srcs = ["internal/seed_seq.cc"],
    hdrs = ["internal/seed_seq.h"],
    deps = [
        ":logging",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_test(
    name = "seed_seq_test",
    srcs = ["internal/seed_seq_test.cc"],
    deps = [
        ":seed_seq",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/types:span",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "serialization",
    srcs = ["internal/serialization.cc"],
    hdrs = ["internal/serialization.h"],
    deps = [
        ":meta",
        "@abseil-cpp//absl/numeric:int128",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_test(
    name = "serialization_test",
    srcs = ["internal/serialization_test.cc"],
    deps = [
        ":serialization",
        ":test_protobuf_cc_proto",
        "@googletest//:gtest_main",
        "@protobuf",
    ],
)

cc_library(
    name = "status",
    srcs = ["internal/status.cc"],
    hdrs = ["internal/status.h"],
    deps = [
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:cord",
    ],
)

cc_library(
    name = "subprocess",
    srcs = ["internal/subprocess.cc"],
    hdrs = ["internal/subprocess.h"],
    deps = [
        ":logging",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
    ],
)

cc_test(
    name = "subprocess_test",
    srcs = ["internal/subprocess_test.cc"],
    deps = [
        ":subprocess",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "table_of_recent_compares",
    hdrs = ["internal/table_of_recent_compares.h"],
    deps = [
        ":type_support",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/random:bit_gen_ref",
        "@abseil-cpp//absl/random:distributions",
    ],
)

cc_test(
    name = "table_of_recent_compares_test",
    srcs = ["internal/table_of_recent_compares_test.cc"],
    deps = [
        ":table_of_recent_compares",
        "@abseil-cpp//absl/random",
        "@googletest//:gtest_main",
    ],
)

proto_library(
    name = "test_protobuf",
    srcs = ["internal/test_protobuf.proto"],
)

cc_proto_library(
    name = "test_protobuf_cc_proto",
    deps = [":test_protobuf"],
)

cc_library(
    name = "type_support",
    srcs = ["internal/type_support.cc"],
    hdrs = ["internal/type_support.h"],
    deps = [
        ":absl_helpers",
        ":meta",
        ":printer",
        "@abseil-cpp//absl/debugging:symbolize",
        "@abseil-cpp//absl/functional:function_ref",
        "@abseil-cpp//absl/numeric:int128",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/time",
    ],
)

cc_test(
    name = "type_support_test",
    srcs = ["internal/type_support_test.cc"],
    deps = [
        ":domain",
        ":meta",
        ":printer",
        ":test_protobuf_cc_proto",
        ":type_support",
        "@abseil-cpp//absl/numeric:int128",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/time",
        "@googletest//:gtest_main",
        "@protobuf",
    ],
)
