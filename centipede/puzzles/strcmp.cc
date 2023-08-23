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

// Centipede puzzle: one 4-byte strcmp. Check the output in the log.
// Disable use_auto_dictionary so that we test other functionality.
// RUN: Run --use_auto_dictionary=false && SolutionIs fUzZ
// RUN: ExpectInLog "TEXT IN STDOUT"
// RUN: ExpectInLog "TEXT IN STDERR"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  constexpr size_t kBufSize = 32;
  char buf[kBufSize];
  if (size >= kBufSize) size = kBufSize - 1;
  memcpy(buf, data, size);
  buf[size] = 0;
  if (strcmp(buf, "fUzZ") == 0) {
    printf("TEXT IN STDOUT\n");
    // abort() does not flush stdout, so if we don't flush it, the output
    // may be lost after abort().
    fflush(stdout);
    fprintf(stderr, "TEXT IN STDERR\n");
    abort();
  }
  return 0;
}
