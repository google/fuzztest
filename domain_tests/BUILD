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

package(default_visibility = ["//visibility:private"])

licenses(["notice"])

cc_test(
    name = "aggregate_combinators_test",
    srcs = ["aggregate_combinators_test.cc"],
    deps = [
        ":domain_testing",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
        "@com_google_absl//absl/types:variant",
        "@com_google_fuzztest//fuzztest:domain_core",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "arbitrary_domains_protobuf_test",
    srcs = ["arbitrary_domains_protobuf_test.cc"],
    deps = [
        ":domain_testing",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/random:bit_gen_ref",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:string_view",
        "@com_google_fuzztest//fuzztest:domain",
        "@com_google_fuzztest//fuzztest:test_protobuf_cc_proto",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "arbitrary_domains_test",
    srcs = ["arbitrary_domains_test.cc"],
    deps = [
        ":domain_testing",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/random:bit_gen_ref",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/time",
        "@com_google_fuzztest//fuzztest:absl_helpers",
        "@com_google_fuzztest//fuzztest:domain_core",
        "@com_google_fuzztest//fuzztest:serialization",
        "@com_google_fuzztest//fuzztest:test_protobuf_cc_proto",
        "@com_google_fuzztest//fuzztest:type_support",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "container_combinators_test",
    srcs = ["container_combinators_test.cc"],
    deps = [
        ":domain_testing",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/strings",
        "@com_google_fuzztest//fuzztest:domain_core",
        "@com_google_fuzztest//fuzztest:type_support",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "container_test",
    srcs = ["container_test.cc"],
    deps = [
        ":domain_testing",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/random",
        "@com_google_fuzztest//fuzztest:coverage",
        "@com_google_fuzztest//fuzztest:domain_core",
        "@com_google_fuzztest//fuzztest:type_support",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "domain_testing",
    testonly = 1,
    hdrs = ["domain_testing.h"],
    visibility = ["@com_google_fuzztest//:__subpackages__"],
    deps = [
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/hash",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/random:bit_gen_ref",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_fuzztest//fuzztest:logging",
        "@com_google_fuzztest//fuzztest:meta",
        "@com_google_fuzztest//fuzztest:serialization",
        "@com_google_fuzztest//fuzztest:test_protobuf_cc_proto",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "in_grammar_domain_test",
    srcs = ["in_grammar_domain_test.cc"],
    deps = [
        ":domain_testing",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/random",
        "@com_google_fuzztest//fuzztest:domain",
        "@com_google_fuzztest//fuzztest:serialization",
        "@com_google_fuzztest//fuzztest/grammars:json_grammar",
        "@com_google_googletest//:gtest_main",
        "@com_nlohmann_json//:json",
    ],
)

cc_test(
    name = "in_regexp_domain_test",
    srcs = ["in_regexp_domain_test.cc"],
    deps = [
        ":domain_testing",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/types:span",
        "@com_google_fuzztest//fuzztest:domain",
        "@com_google_fuzztest//fuzztest:logging",
        "@com_google_fuzztest//fuzztest:type_support",
        "@com_google_googletest//:gtest_main",
        "@com_googlesource_code_re2//:re2",
    ],
)

cc_test(
    name = "map_filter_combinator_test",
    srcs = ["map_filter_combinator_test.cc"],
    deps = [
        ":domain_testing",
        "@com_google_absl//absl/algorithm:container",
        "@com_google_absl//absl/random",
        "@com_google_fuzztest//fuzztest:domain_core",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "misc_domains_test",
    srcs = ["misc_domains_test.cc"],
    deps = [
        ":domain_testing",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/numeric:int128",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/types:span",
        "@com_google_fuzztest//fuzztest:domain_core",
        "@com_google_fuzztest//fuzztest:meta",
        "@com_google_fuzztest//fuzztest:type_support",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "numeric_domains_test",
    srcs = ["numeric_domains_test.cc"],
    deps = [
        ":domain_testing",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/numeric:int128",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_fuzztest//fuzztest:domain_core",
        "@com_google_fuzztest//fuzztest:serialization",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "pointer_domains_test",
    srcs = ["pointer_domains_test.cc"],
    deps = [
        ":domain_testing",
        "@com_google_absl//absl/random",
        "@com_google_fuzztest//fuzztest:domain_core",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "recursive_domains_test",
    srcs = ["recursive_domains_test.cc"],
    deps = [
        ":domain_testing",
        "@com_google_absl//absl/random",
        "@com_google_fuzztest//fuzztest:domain_core",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "specific_value_domains_test",
    srcs = ["specific_value_domains_test.cc"],
    deps = [
        ":domain_testing",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:span",
        "@com_google_fuzztest//fuzztest:domain_core",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "string_domains_test",
    srcs = ["string_domains_test.cc"],
    deps = [
        ":domain_testing",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/random",
        "@com_google_fuzztest//fuzztest:domain_core",
        "@com_google_googletest//:gtest_main",
    ],
)
