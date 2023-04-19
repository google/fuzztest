// Copyright 2022 The Centipede Authors.
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

// A fuzz target used for testing Centipede.
// Induces an Abort.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Print "I AM ABOUT TO ABORT" and abort, if the input is 'AbOrT'.
  // Used by exit_on_crash_test.sh.
  if (size == 5 && data[0] == 'A' && data[1] == 'b' && data[2] == 'O' &&
      data[3] == 'r' && data[4] == 'T') {
    fprintf(stderr, "I AM ABOUT TO ABORT\n");
    abort();
  }
  return 0;
}
