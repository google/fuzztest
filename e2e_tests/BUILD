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

# Can be run with or without `--config=fuzztest`. When running without, the
# fuzzing mode tests are skipped.
cc_test(
    name = "functional_test",
    timeout = "long",
    srcs = ["functional_test.cc"],
    data = [
        "@com_google_fuzztest//centipede:centipede_uninstrumented",
        "@com_google_fuzztest//e2e_tests/testdata:fuzz_tests_for_functional_testing.stripped",
        "@com_google_fuzztest//e2e_tests/testdata:fuzz_tests_with_invalid_seeds.stripped",
    ],
    defines = select({
        "@com_google_fuzztest//fuzztest:use_centipede": ["FUZZTEST_USE_CENTIPEDE"],
        "//conditions:default": [],
    }),
    shard_count = 50,
    deps = [
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@com_google_fuzztest//fuzztest:io",
        "@com_google_fuzztest//fuzztest:logging",
        "@com_google_fuzztest//fuzztest:serialization",
        "@com_google_fuzztest//fuzztest:subprocess",
        "@com_google_fuzztest//fuzztest:type_support",
        "@com_google_googletest//:gtest_main",
        "@com_googlesource_code_re2//:re2",
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
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@com_google_fuzztest//fuzztest:logging",
        "@com_google_fuzztest//fuzztest:subprocess",
        "@com_googlesource_code_re2//:re2",
    ],
)
