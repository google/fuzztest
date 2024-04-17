# Copyright 2023 Google LLC
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

licenses(["notice"])

cc_library(
    name = "antlr4-cpp-runtime",
    srcs = glob(["runtime/src/**/*.cpp"]),
    hdrs = ["runtime/src/antlr4-runtime.h"],
    copts = ["-fexceptions"],
    defines = ["ANTLR4CPP_USING_ABSEIL"],
    features = ["-use_header_modules"],
    includes = ["runtime/src"],
    textual_hdrs = glob(
        ["runtime/src/**/*.h"],
        exclude = ["runtime/src/antlr4-runtime.h"],
    ),
    visibility = ["//visibility:public"],
    deps = [
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/synchronization",
    ],
)