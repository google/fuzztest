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

load("@rules_rust//rust:defs.bzl", "rust_clippy", "rust_library")

licenses(["notice"])

rust_library(
    name = "engine",
    srcs = [
        "src/engine_ffi.rs",
        "src/lib.rs",
    ],
    edition = "2024",
    visibility = ["@com_google_fuzztest//rust:__subpackages__"],
    deps = [
        "@com_google_fuzztest//centipede:engine_abi",
        "@com_google_fuzztest//centipede:engine_controller_with_subprocess",
        "@com_google_fuzztest//centipede:engine_worker",
    ],
)

rust_clippy(
    name = "engine_clippy",
    deps = [
        ":engine",
    ],
)
