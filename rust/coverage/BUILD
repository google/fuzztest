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

load("@rules_rust//rust:defs.bzl", "rust_clippy", "rust_library", "rust_test")

licenses(["notice"])

rust_library(
    name = "coverage",
    srcs = [
        "src/coverage.rs",
        "src/lib.rs",
    ],
    edition = "2024",
    visibility = ["@com_google_fuzztest//rust:__subpackages__"],
    deps = [
        "@com_google_fuzztest//centipede:sancov_runtime",
    ],
)

rust_test(
    name = "coverage_test",
    # Avoid interference on coverage collection between threads.
    args = ["--test-threads=1"],
    crate = ":coverage",
    edition = "2024",
    env = {
        "CENTIPEDE_RUNNER_FLAGS": ":use_cmp_features:",
    },
    # TODO: b/437896409 - Replace with global config once it's available.
    rustc_flags = [
        "-Cpasses=sancov-module",
        "-Cllvm-args=-sanitizer-coverage-level=1",
        "-Cllvm-args=-sanitizer-coverage-trace-compares",
    ],
    deps = [
        "@crate_index//:googletest",
    ],
)

rust_clippy(
    name = "coverage_clippy",
    deps = [
        ":coverage",
    ],
)
