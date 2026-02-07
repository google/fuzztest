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

# Domain API tests.

load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

package(default_visibility = ["//visibility:private"])

licenses(["notice"])

cc_test(
    name = "aggregate_combinators_test",
    srcs = ["aggregate_combinators_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/random:bit_gen_ref",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/types:optional",
        "@abseil-cpp//absl/types:span",
        "@abseil-cpp//absl/types:variant",
        "@fuzztest//fuzztest:domain_core",
        "@fuzztest//fuzztest/internal:serialization",
        "@fuzztest//fuzztest/internal:type_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "arbitrary_domains_flatbuffers_test",
    srcs = ["arbitrary_domains_flatbuffers_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/status",
        "@fuzztest//fuzztest:domain",
        "@fuzztest//fuzztest:flatbuffers",
        "@fuzztest//fuzztest:fuzztest_macros",
        "@fuzztest//fuzztest/internal:meta",
        "@fuzztest//fuzztest/internal:test_flatbuffers_cc_fbs",
        "@flatbuffers//:runtime_cc",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "arbitrary_domains_protobuf_test",
    srcs = ["arbitrary_domains_protobuf_test.cc"],
    tags = ["cpu:4"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/random:bit_gen_ref",
        "@abseil-cpp//absl/random:seed_sequences",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/time",
        "@fuzztest//fuzztest:domain",
        "@fuzztest//fuzztest/internal:test_protobuf_cc_proto",
        "@googletest//:gtest_main",
        "@protobuf",
    ],
)

cc_test(
    name = "arbitrary_domains_test",
    srcs = ["arbitrary_domains_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/random:bit_gen_ref",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/time",
        "@fuzztest//fuzztest:domain_core",
        "@fuzztest//fuzztest/internal:serialization",
        "@fuzztest//fuzztest/internal:test_protobuf_cc_proto",
        "@fuzztest//fuzztest/internal:type_support",
        "@fuzztest//fuzztest/internal/domains:core_domains_impl",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "bitgen_ref_domain_test",
    srcs = ["bitgen_ref_domain_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/random:bit_gen_ref",
        "@fuzztest//fuzztest:domain_core",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "container_combinators_test",
    srcs = ["container_combinators_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/strings",
        "@fuzztest//fuzztest:domain_core",
        "@fuzztest//fuzztest/internal:meta",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "container_test",
    srcs = ["container_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/random",
        "@fuzztest//fuzztest:domain_core",
        "@fuzztest//fuzztest/internal:table_of_recent_compares",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "domain_testing",
    testonly = 1,
    hdrs = ["domain_testing.h"],
    visibility = ["@fuzztest//:__subpackages__"],
    deps = [
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/hash",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/random:bit_gen_ref",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@fuzztest//common:logging",
        "@fuzztest//fuzztest/internal:logging",
        "@fuzztest//fuzztest/internal:meta",
        "@fuzztest//fuzztest/internal:serialization",
        "@fuzztest//fuzztest/internal:test_protobuf_cc_proto",
        "@fuzztest//fuzztest/internal/domains:core_domains_impl",
        "@googletest//:gtest",
        "@protobuf",
    ],
)

cc_test(
    name = "in_grammar_domain_test",
    srcs = ["in_grammar_domain_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/random",
        "@fuzztest//fuzztest:domain",
        "@fuzztest//fuzztest/grammars:json_grammar",
        "@fuzztest//fuzztest/internal:serialization",
        "@googletest//:gtest_main",
        "@nlohmann_json//:json",
    ],
)

cc_test(
    name = "in_regexp_domain_test",
    srcs = ["in_regexp_domain_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/random",
        "@fuzztest//fuzztest:domain",
        "@googletest//:gtest_main",
        "@re2",
    ],
)

cc_test(
    name = "map_filter_combinator_test",
    srcs = ["map_filter_combinator_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/algorithm:container",
        "@abseil-cpp//absl/random",
        "@fuzztest//fuzztest:domain_core",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "misc_domains_test",
    srcs = ["misc_domains_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/numeric:int128",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/types:span",
        "@fuzztest//fuzztest:domain_core",
        "@fuzztest//fuzztest/internal:meta",
        "@fuzztest//fuzztest/internal:serialization",
        "@fuzztest//fuzztest/internal:type_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "numeric_domains_test",
    srcs = ["numeric_domains_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/numeric:int128",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@fuzztest//fuzztest:domain_core",
        "@fuzztest//fuzztest/internal:serialization",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "pointer_domains_test",
    srcs = ["pointer_domains_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/random",
        "@fuzztest//fuzztest:domain_core",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "recursive_domains_test",
    srcs = ["recursive_domains_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/random",
        "@fuzztest//fuzztest:domain_core",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "specific_value_domains_test",
    srcs = ["specific_value_domains_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/time",
        "@abseil-cpp//absl/types:span",
        "@fuzztest//fuzztest:domain_core",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "string_domains_test",
    srcs = ["string_domains_test.cc"],
    deps = [
        ":domain_testing",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/random",
        "@fuzztest//fuzztest:domain_core",
        "@fuzztest//fuzztest/internal:table_of_recent_compares",
        "@googletest//:gtest_main",
    ],
)
