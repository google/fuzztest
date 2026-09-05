# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

licenses(["notice"])

exports_files(["BUILD"])

rust_library(
    name = "fuzztest",
    srcs = glob([
        "src/**/*.rs",
    ]),
    edition = "2024",
    proc_macro_deps = [
        "@com_google_fuzztest//rust/fuzztest_macro:fuzztest_macro",
    ],
    visibility = [
        "//cloud/vmm/public:__subpackages__",
        "@com_google_fuzztest//rust:__subpackages__",
    ],
    deps = [
        "@com_google_fuzztest//rust/coverage",
        "@com_google_fuzztest//rust/engine",
        "@com_google_fuzztest//rust/options:fuzztest_options",
        "@crate_index//:anyhow",  # v1
        "@crate_index//:clap",  # v4
        "@crate_index//:humantime",  # v2
        "@crate_index//:inventory",  # v0_3
        "@crate_index//:num-traits",
        "@crate_index//:postcard",  # v1
        "@crate_index//:rand",  # v0_10
        "@crate_index//:serde",  # v1
        "@crate_index//:spin",  # v0_10
        "@crate_index//:tempfile",  # v3
    ],
)

rust_test(
    name = "fuzztest_test",
    # Avoid interference when setting/resetting environment variables in tests.
    args = ["--test-threads=1"],
    crate = ":fuzztest",
    edition = "2024",
    deps = [
        "@crate_index//:googletest",
    ],
)
