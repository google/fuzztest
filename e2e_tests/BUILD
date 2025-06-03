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

# End-to-end tests with microbenchmarks.

package(default_visibility = ["//visibility:private"])

licenses(["notice"])

cc_library(
    name = "test_binary_util",
    testonly = 1,
    srcs = ["test_binary_util.cc"],
    hdrs = ["test_binary_util.h"],
    deps = [
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/time",
        "@com_google_fuzztest//fuzztest/internal:flag_name",
        "@com_google_fuzztest//fuzztest/internal:subprocess",
    ],
)

# Can be run with or without `--config=fuzztest`. When running without, the
# fuzzing mode tests are skipped.
cc_test(
    name = "functional_test",
    timeout = "long",
    srcs = ["functional_test.cc"],
    data = [
        "@com_google_fuzztest//centipede:centipede_uninstrumented",
        "@com_google_fuzztest//e2e_tests/testdata:data",
        "@com_google_fuzztest//e2e_tests/testdata:dynamically_registered_fuzz_tests.stripped",
        "@com_google_fuzztest//e2e_tests/testdata:fuzz_tests_for_functional_testing.stripped",
        "@com_google_fuzztest//e2e_tests/testdata:fuzz_tests_with_invalid_seeds.stripped",
        "@com_google_fuzztest//e2e_tests/testdata:llvm_fuzzer_with_custom_mutator.stripped",
        "@com_google_fuzztest//e2e_tests/testdata:unit_test_and_fuzz_tests.stripped",
    ],
    defines = select({
        "@com_google_fuzztest//fuzztest:use_centipede": ["FUZZTEST_USE_CENTIPEDE"],
        "//conditions:default": [],
    }),
    shard_count = 50,
    tags = [
        # Don't cache the results.
        "external",
    ],
    deps = [
        ":test_binary_util",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/time",
        "@com_google_fuzztest//centipede:weak_sancov_stubs",
        "@com_google_fuzztest//common:temp_dir",
        "@com_google_fuzztest//fuzztest/internal:escaping",
        "@com_google_fuzztest//fuzztest/internal:io",
        "@com_google_fuzztest//fuzztest/internal:logging",
        "@com_google_fuzztest//fuzztest/internal:printer",
        "@com_google_fuzztest//fuzztest/internal:serialization",
        "@com_google_fuzztest//fuzztest/internal:subprocess",
        "@com_google_fuzztest//fuzztest/internal:type_support",
        "@googletest//:gtest_main",
        "@re2",
    ],
)

# Must be run with `--config=fuzztest`, as it benchmarks fuzzing mode, which
# needs coverage instrumentation.
cc_binary(
    name = "benchmark_test",
    testonly = 1,
    srcs = ["benchmark_test.cc"],
    data = ["@com_google_fuzztest//e2e_tests/testdata:fuzz_tests_for_microbenchmarking.stripped"],
    deps = [
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/time",
        "@com_google_fuzztest//fuzztest/internal:logging",
        "@com_google_fuzztest//fuzztest/internal:subprocess",
        "@re2",
    ],
)

# Must be run with `--config=libfuzzer`
cc_test(
    name = "compatibility_mode_test",
    timeout = "long",
    srcs = ["compatibility_mode_test.cc"],
    data = [
        "@com_google_fuzztest//e2e_tests/testdata:fuzz_tests_for_functional_testing.stripped",
    ],
    tags = [
        # Don't cache the results.
        "external",
        # Don't include in wildcard expansions (:..., :all).
        "manual",
    ],
    deps = [
        ":test_binary_util",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
        "@com_google_fuzztest//common:temp_dir",
        "@com_google_fuzztest//fuzztest/internal:io",
        "@com_google_fuzztest//fuzztest/internal:subprocess",
        "@googletest//:gtest_main",
    ],
)

# Must be run with `--config=fuzztest-experimental --config=asan`.
cc_test(
    name = "corpus_database_test",
    size = "large",
    srcs = ["corpus_database_test.cc"],
    data = [
        "@com_google_fuzztest//centipede:centipede_uninstrumented",
        "@com_google_fuzztest//e2e_tests/testdata:fuzz_tests_for_corpus_database_testing.stripped",
    ],
    local_defines = select({
        "@com_google_fuzztest//fuzztest:use_centipede": ["FUZZTEST_USE_CENTIPEDE"],
        "//conditions:default": [],
    }),
    tags = [
        # Don't cache the results.
        "external",
        # Don't include in wildcard expansions (:..., :all).
        "manual",
    ],
    deps = [
        ":test_binary_util",
        "@abseil-cpp//absl/base:no_destructor",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
        "@com_google_fuzztest//centipede:weak_sancov_stubs",
        "@com_google_fuzztest//common:temp_dir",
        "@com_google_fuzztest//fuzztest/internal:escaping",
        "@com_google_fuzztest//fuzztest/internal:io",
        "@com_google_fuzztest//fuzztest/internal:logging",
        "@com_google_fuzztest//fuzztest/internal:subprocess",
        "@googletest//:gtest_main",
    ],
)
