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

load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_clippy", "rust_library", "rust_test")

licenses(["notice"])

rust_library(
    name = "cargo_fuzztest",
    srcs = ["src/lib.rs"],
    edition = "2024",
    visibility = ["@com_google_fuzztest//rust:__subpackages__"],
    deps = [
        "@crate_index//:anyhow",  # v1
        "@crate_index//:clap",  # v4
        "@crate_index//:serde",  # v1
        "@crate_index//:serde_json",  # v1
    ],
)

rust_binary(
    name = "cargo_fuzztest_bin",
    srcs = ["src/main.rs"],
    edition = "2024",
    visibility = ["@com_google_fuzztest//rust:__subpackages__"],
    deps = [
        ":cargo_fuzztest",
        "@crate_index//:anyhow",  # v1
        "@crate_index//:clap",  # v4
    ],
)

rust_test(
    name = "cargo_fuzztest_lib_test",
    crate = ":cargo_fuzztest",
    edition = "2024",
    deps = [
        "@crate_index//:googletest",
    ],
)

rust_clippy(
    name = "cargo_fuzztest_clippy",
    deps = [
        ":cargo_fuzztest",
        ":cargo_fuzztest_bin",
    ],
)
