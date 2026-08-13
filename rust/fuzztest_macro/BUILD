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

load("@rules_rust//rust:defs.bzl", "rust_proc_macro", "rust_test")

licenses(["notice"])

rust_proc_macro(
    name = "fuzztest_macro",
    srcs = glob(
        [
            "src/**/*.rs",
        ],
        exclude = ["src/test_main.rs"],
    ),
    edition = "2024",
    visibility = ["@com_google_fuzztest//rust:__subpackages__"],
    deps = [
        "@crate_index//:convert_case",  # v0_4
        "@crate_index//:proc-macro-crate",
        "@crate_index//:proc-macro2",
        "@crate_index//:quote",  # v1
        "@crate_index//:syn",  # v2
    ],
)

rust_test(
    name = "fuzztest_macro_test",
    srcs = glob(
        ["src/**/*.rs"],
        exclude = ["src/lib.rs"],
    ),
    crate_root = "src/test_main.rs",
    edition = "2024",
    proc_macro_deps = [":fuzztest_macro"],
    deps = [
        "@crate_index//:convert_case",  # v0_4
        "@crate_index//:googletest",
        "@crate_index//:proc-macro-crate",
        "@crate_index//:proc-macro2",
        "@crate_index//:quote",  # v1
        "@crate_index//:syn",  # v2
    ],
)
