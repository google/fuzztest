# Copyright 2023 Google LLC
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

package(default_visibility = [
    "@com_google_fuzztest//e2e_tests/testdata:__pkg__",
    "@com_google_fuzztest//fuzztest:__subpackages__",
])

load("@bazel_skylib//rules:common_settings.bzl", "bool_flag")

bool_flag(
    name = "enable_rpc_fuzzing",
    build_setting_default = False,
    visibility = ["//visibility:public"],
)

config_setting(
    name = "rpc_fuzzing_is_enabled",
    flag_values = {
        ":enable_rpc_fuzzing": "true",
    },
)

cc_library(
    name = "proto_field_path",
    srcs = ["proto_field_path.cc"],
    hdrs = ["proto_field_path.h"],
    target_compatible_with = select({
        ":rpc_fuzzing_is_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    deps = [
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/strings",
        "@com_google_fuzztest//fuzztest:logging",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "proto_field_path_test",
    srcs = ["proto_field_path_test.cc"],
    deps = [
        ":proto_field_path",
        "@com_google_fuzztest//fuzztest:test_protobuf_cc_proto",
        "@com_google_fuzztest//rpc_fuzzing/testdata:mini_blogger_cc_proto",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "rpc_sequence",
    srcs = ["rpc_sequence.cc"],
    hdrs = ["rpc_sequence.h"],
    deps = [
        ":proto_field_path",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/random:bit_gen_ref",
        "@com_google_fuzztest//fuzztest:logging",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "rpc_sequence_test",
    srcs = ["rpc_sequence_test.cc"],
    deps = [
        ":proto_field_path",
        ":rpc_sequence",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/log:check",
        "@com_google_fuzztest//rpc_fuzzing/testdata:mini_blogger_cc_proto",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
    ],
)

# TODO(changochen): Combine the stubs into a single lib.
cc_library(
    name = "rpc_stub",
    hdrs = ["rpc_stub.h"],
    deps = [
        "@com_google_absl//absl/status:statusor",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "grpc_stub",
    srcs = ["grpc_stub.cc"],
    hdrs = ["grpc_stub.h"],
    deps = [
        ":rpc_stub",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_codegen_proto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "rpc_executor",
    srcs = ["rpc_executor.cc"],
    hdrs = ["rpc_executor.h"],
    deps = [
        ":rpc_sequence",
        ":rpc_stub",
        "@com_google_absl//absl/log:die_if_null",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_fuzztest//fuzztest:logging",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "rpc_executor_test",
    srcs = ["rpc_executor_test.cc"],
    deps = [
        ":grpc_stub",
        ":proto_field_path",
        ":rpc_executor",
        ":rpc_sequence",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
        "@com_google_fuzztest//domain_tests:domain_testing",
        "@com_google_fuzztest//rpc_fuzzing/testdata:mini_blogger_cc_proto",
        "@com_google_fuzztest//rpc_fuzzing/testdata:mini_blogger_grpc_service",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "rpc_potential_dfg",
    srcs = ["rpc_potential_dfg.cc"],
    hdrs = ["rpc_potential_dfg.h"],
    deps = [
        ":proto_field_path",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
        "@com_google_fuzztest//fuzztest:logging",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "rpc_potential_dfg_test",
    srcs = ["rpc_potential_dfg_test.cc"],
    deps = [
        ":proto_field_path",
        ":rpc_potential_dfg",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_fuzztest//rpc_fuzzing/testdata:mini_blogger_cc_grpc_proto",
        "@com_google_fuzztest//rpc_fuzzing/testdata:mini_blogger_cc_proto",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "rpc_session",
    hdrs = ["rpc_session.h"],
    deps = [
        ":proto_field_path",
        ":rpc_executor",
        ":rpc_potential_dfg",
        ":rpc_sequence",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/random:bit_gen_ref",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_fuzztest//fuzztest:domain",
        "@com_google_fuzztest//fuzztest:domain_core",
        "@com_google_fuzztest//fuzztest:logging",
        "@com_google_fuzztest//fuzztest:serialization",
        "@com_google_fuzztest//fuzztest:table_of_recent_compares",
        "@com_google_fuzztest//fuzztest:type_support",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "rpc_session_test",
    srcs = ["rpc_session_test.cc"],
    deps = [
        ":proto_field_path",
        ":rpc_potential_dfg",
        ":rpc_sequence",
        ":rpc_session",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/random",
        "@com_google_fuzztest//domain_tests:domain_testing",
        "@com_google_fuzztest//fuzztest:serialization",
        "@com_google_fuzztest//rpc_fuzzing/testdata:mini_blogger_cc_grpc_proto",
        "@com_google_fuzztest//rpc_fuzzing/testdata:mini_blogger_cc_proto",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
    ],
)
