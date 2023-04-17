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

# Testdata binaries for end-to-end tests.
#
# The binaries in this package contain a set of small fuzz tests that are used
# by `functional_test` and `benchmark_test`.

package(default_visibility = ["//e2e_tests:__pkg__"])

licenses(["notice"])

# This binary contains "puzzles" for the fuzzer engine. The `functional_test`
# runs them to check that the fuzzer can "solve" each puzzle (find the target
# branch). The `benchmark_test` on the other hand measures how long it takes the
# fuzzer to solve each fuzz test.
cc_binary(
    name = "fuzz_tests_for_microbenchmarking",
    testonly = 1,
    srcs = ["fuzz_tests_for_microbenchmarking.cc"],
    deps = [
        "@com_google_fuzztest//fuzztest",
        "@com_google_fuzztest//fuzztest:fuzztest_gtest_main",
        "@com_google_fuzztest//fuzztest:test_protobuf_cc_proto",
    ],
)

# The following binaries contain fuzz tests that are not for benchmarking, but
# for functional testing only, i.e., to be used by `functional_test` only.
cc_binary(
    name = "fuzz_tests_for_functional_testing",
    testonly = 1,
    srcs = [
        "fuzz_tests_for_functional_testing.cc",
        "fuzz_tests_for_microbenchmarking.cc",
        "fuzz_tests_using_googletest.cc",
    ],
    deps = [
        "@com_google_absl//absl/algorithm:container",
        "@com_google_absl//absl/functional:function_ref",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@com_google_fuzztest//fuzztest",
        "@com_google_fuzztest//fuzztest:fuzztest_gtest_main",
        "@com_google_fuzztest//fuzztest:googletest_fixture_adapter",
        "@com_google_fuzztest//fuzztest:test_protobuf_cc_proto",
        "@com_google_protobuf//:protobuf",
    ],
)

# Must be a separate binary, as the invalid seeds make the binary crash at
# process start time. Used by `functional_test` only.
cc_binary(
    name = "fuzz_tests_with_invalid_seeds",
    testonly = 1,
    srcs = ["fuzz_tests_with_invalid_seeds.cc"],
    deps = [
        "@com_google_fuzztest//fuzztest",
        "@com_google_fuzztest//fuzztest:fuzztest_gtest_main",
    ],
)
