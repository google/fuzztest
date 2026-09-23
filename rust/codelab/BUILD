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

# The Escaping Library example for the Rust FuzzTest Codelab.

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(default_visibility = ["//visibility:private"])

licenses(["notice"])

rust_library(
    name = "escaping",
    srcs = ["escaping.rs"],
    crate_root = "escaping.rs",
    edition = "2024",
)

rust_test(
    name = "escaping_test",
    srcs = ["escaping_test.rs"],
    crate_root = "escaping_test.rs",
    edition = "2024",
    deps = [
        ":escaping",
        "@com_google_fuzztest//rust:fuzztest",
        "@crate_index//:googletest",
    ],
)
