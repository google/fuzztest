# Copyright 2026 Google LLC
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

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

licenses(["notice"])

rust_test(
    name = "worker_test",
    srcs = ["worker_test.rs"],
    data = [
        "@com_google_fuzztest//rust/e2e_tests/testdata:fuzztest_main",
    ],
    edition = "2024",
    deps = [
        ":test_utils",
        "@crate_index//:googletest",
    ],
)

rust_test(
    name = "standalone_mode_test",
    srcs = ["standalone_mode_test.rs"],
    data = [
        "@com_google_fuzztest//centipede:centipede_uninstrumented",
        "@com_google_fuzztest//rust/e2e_tests/testdata:fuzztest_main",
        "@com_google_fuzztest//rust/e2e_tests/testdata:standalone_fuzz_tests_bin",
    ],
    edition = "2024",
    deps = [
        ":test_utils",
        "@crate_index//:googletest",
    ],
)

rust_test(
    name = "worker_with_centipede_test",
    srcs = ["worker_with_centipede_test.rs"],
    data = [
        "@com_google_fuzztest//centipede:centipede_uninstrumented",
        "@com_google_fuzztest//rust/e2e_tests/testdata:fuzztest_main",
    ],
    edition = "2024",
    deps = [
        ":test_utils",
        "@crate_index//:googletest",
        "@crate_index//:rand",  # v0_10
    ],
)

rust_test(
    name = "worker_with_centipede_sanitizer_test",
    srcs = ["worker_with_centipede_sanitizer_test.rs"],
    data = [
        "@com_google_fuzztest//centipede:centipede_uninstrumented",
        "@com_google_fuzztest//rust/e2e_tests/testdata:fuzztest_main",
    ],
    edition = "2024",
    deps = [
        ":test_utils",
        "@crate_index//:googletest",
    ],
)

rust_library(
    name = "test_utils",
    testonly = 1,
    srcs = ["test_utils.rs"],
    edition = "2024",
    deps = [
        "@crate_index//:googletest",
    ],
)

rust_test(
    name = "gtest_registration_test",
    srcs = ["gtest_registration_test.rs"],
    data = [
        "@com_google_fuzztest//rust/e2e_tests/testdata:fuzz_tests_as_gtests",
    ],
    edition = "2024",
    deps = [
        ":test_utils",
        "@crate_index//:googletest",
    ],
)

rust_test(
    name = "replay_test",
    srcs = ["replay_test.rs"],
    data = [
        "@com_google_fuzztest//centipede:centipede_uninstrumented",
        "@com_google_fuzztest//rust/e2e_tests/testdata:replay_fuzz_tests_bin",
    ],
    edition = "2024",
    deps = [
        ":test_utils",
        "@crate_index//:googletest",
    ],
)
