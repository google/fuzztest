# Copyright 2025 The Centipede Authors.
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

package(default_compatible_with = ["//buildenv/target:non_prod"])

licenses(["notice"])

# Debugging tools

cc_binary(
    name = "feature_analyzer",
    srcs = ["feature_analyzer.cc"],
    deps = [
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings:string_view",
        "@com_google_fuzztest//centipede:feature",
        "@com_google_fuzztest//centipede:util",
        "@com_google_fuzztest//common:blob_file",
        "@com_google_fuzztest//common:defs",
        "@com_google_fuzztest//common:logging",
    ],
)
