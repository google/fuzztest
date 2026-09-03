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

load("@rules_rust//rust:defs.bzl", "rust_test")

package(default_visibility = ["@com_google_fuzztest//rust/e2e_tests:__subpackages__"])

licenses(["notice"])

rust_test(
    name = "fuzztest_main",
    testonly = 1,
    srcs = [
        "fuzz_tests.rs",
    ],
    edition = "2024",
    # TODO: b/437896409 - Replace with global config once it's available.
    rustc_flags = [
        "-Ccodegen-units=1",
        "-Clink-dead-code",
        "-Cpasses=sancov-module",
        "-Cllvm-args=-sanitizer-coverage-level=1",
        "-Cllvm-args=-sanitizer-coverage-trace-compares",
    ],
    tags = [
        "manual",
        "notap",
    ],
    deps = [
        "@com_google_fuzztest//rust:fuzztest",
        "@crate_index//:anyhow",  # v1
        "@crate_index//:googletest",
        "@crate_index//:inventory",  # v0_3
        "@crate_index//:rand",  # v0_10
    ],
)

rust_test(
    name = "standalone_fuzz_tests_bin",
    testonly = 1,
    srcs = [
        "standalone_fuzz_tests.rs",
    ],
    edition = "2024",
    rustc_flags = [
        "-Ccodegen-units=1",
        "-Clink-dead-code",
        "-Cpasses=sancov-module",
        "-Cllvm-args=-sanitizer-coverage-level=1",
        "-Cllvm-args=-sanitizer-coverage-trace-compares",
    ],
    tags = [
        "manual",
        "notap",
    ],
    deps = [
        "@com_google_fuzztest//rust:fuzztest",
        "@crate_index//:anyhow",  # v1
        "@crate_index//:googletest",
        "@crate_index//:inventory",  # v0_3
        "@crate_index//:rand",  # v0_10
    ],
)

rust_test(
    name = "replay_fuzz_tests_bin",
    testonly = 1,
    srcs = [
        "replay_fuzz_tests.rs",
    ],
    edition = "2024",
    rustc_flags = [
        "-Ccodegen-units=1",
        "-Clink-dead-code",
        "-Cpasses=sancov-module",
        "-Cllvm-args=-sanitizer-coverage-level=1",
        "-Cllvm-args=-sanitizer-coverage-trace-compares",
    ],
    tags = [
        "manual",
        "notap",
    ],
    deps = [
        "@com_google_fuzztest//rust:fuzztest",
        "@crate_index//:anyhow",  # v1
        "@crate_index//:googletest",
        "@crate_index//:inventory",  # v0_3
        "@crate_index//:rand",  # v0_10
    ],
)

rust_test(
    name = "fuzz_tests_as_gtests",
    srcs = ["fuzz_tests_as_gtests.rs"],
    edition = "2024",
    tags = [
        "manual",
        "notap",
    ],
    deps = [
        "@com_google_fuzztest//rust:fuzztest",
        "@crate_index//:anyhow",  # v1
        "@crate_index//:googletest",
        "@crate_index//:inventory",  # v0_3
        "@crate_index//:postcard",  # v1
        "@crate_index//:rand",  # v0_10
    ],
)
