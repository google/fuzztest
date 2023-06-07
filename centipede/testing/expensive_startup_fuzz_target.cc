// Copyright 2023 The Centipede Authors.
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

#include <cstddef>
#include <cstdint>
#include <cstdio>

static int sink;

// Instrumented function that runs at startup. We want it's coverage ignored.
__attribute__((constructor, noinline)) void Startup() {
  fprintf(stderr, "Startup\n");
  // Function entry: generate a coverage feature.
  sink++;                    // generate data flow feature
  if (sink == (sink == 42))  // generate some cmp features
    Startup();
}

// A fuzz target used for testing Centipede.
// Does nothing, returns 0. There is a startup code that runs before the target.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return 0;
}
