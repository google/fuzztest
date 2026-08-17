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

exports_files(["BUILD"])

rust_library(
    name = "fuzztest_options",
    srcs = glob([
        "src/**/*.rs",
    ]),
    edition = "2024",
    visibility = ["@com_google_fuzztest//rust:__subpackages__"],
    deps = [
        "@crate_index//:anyhow",  # v1
        "@crate_index//:clap",  # v4
        "@crate_index//:humantime",  # v2
    ],
)

rust_test(
    name = "fuzztest_options_test",
    # Avoid interference when setting/resetting environment variables in tests.
    args = ["--test-threads=1"],
    crate = ":fuzztest_options",
    edition = "2024",
    deps = [
        "@crate_index//:googletest",
    ],
)

rust_clippy(
    name = "fuzztest_options_clippy",
    deps = [
        ":fuzztest_options",
    ],
)
