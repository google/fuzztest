# Copyright 2024 Google LLC
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

# The package contains libraries that are common to both FuzzTest and Centipede.

VISIBILITY = ["//visibility:public"]

PUBLIC_API_VISIBILITY = VISIBILITY

package(default_visibility = VISIBILITY)

licenses(["notice"])

### Files

# Centipede runner needs access to this file, since it has special build
# requirements and needs to compile the file directly with specific flags.
exports_files(
    srcs = ["defs.h"],
    visibility = ["@com_google_fuzztest//centipede:__pkg__"],
)

### Libraries

cc_library(
    name = "defs",
    hdrs = ["defs.h"],
    visibility = PUBLIC_API_VISIBILITY,
    deps = ["@com_google_absl//absl/types:span"],
)
