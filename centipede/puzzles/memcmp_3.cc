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

// Centipede puzzle: one 3-byte memcmp. Check the output in the log.
// Disable use_auto_dictionary so that we test other functionality.
// RUN: Run --use_auto_dictionary=false && SolutionIs fUz
// RUN: ExpectInLog "TEXT IN STDOUT"
// RUN: ExpectInLog "TEXT IN STDERR"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

auto volatile memcmp_no_inline = &memcmp;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 3 && memcmp_no_inline(data, "fUz", 3) == 0) {
    printf("TEXT IN STDOUT\n");
    // abort() does not flush stdout, so if we don't flush it, the output
    // may be lost after abort().
    fflush(stdout);
    fprintf(stderr, "TEXT IN STDERR\n");
    abort();
  }
  return 0;
}
