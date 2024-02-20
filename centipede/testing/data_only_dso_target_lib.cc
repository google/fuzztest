// Copyright 2024 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Here we try to produce a DSO with an empty sancov PC table. This is done by
// building the library with unused code and enable -gc-sections in lld. Note
// that GNU ld would not produce the intended result.

#include "./centipede/testing/data_only_dso_target_lib.h"

const char kCrashInputData[] = "GoCrash";
const char* crash_input = kCrashInputData;
// Exclude the terminating \0.
const int crash_input_size = sizeof(kCrashInputData) - 1;

// With -gc-sections this function should be removed by the linker.
__attribute__((visibility("hidden"))) int unused_function(int x) {
  return x + 1;
}
