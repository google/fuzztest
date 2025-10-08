// Copyright 2025 The Centipede Authors.
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

// Centipede puzzle: one 3-byte strncasecmp and one 3-byte strcasecmp. Check
// the output in the log. Disable use_auto_dictionary so that we test other
// functionality.
// RUN: Run --use_auto_dictionary=false && SolutionIs 123456
// RUN: ExpectInLog "TEXT IN STDOUT"
// RUN: ExpectInLog "TEXT IN STDERR"

#include <strings.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  constexpr size_t kBufSize = 10;
  if (size > kBufSize - 1) return 0;
  char buf[kBufSize];
  std::memcpy(buf, data, size);
  buf[size] = 0;
  if (strncasecmp(buf, "1239", 3) == 0 && strcasecmp(buf + 3, "456") == 0) {
    std::printf("TEXT IN STDOUT\n");
    // abort() does not flush stdout, so if we don't flush it, the output
    // may be lost after abort().
    std::fflush(stdout);
    std::fprintf(stderr, "TEXT IN STDERR\n");
    std::abort();
  }
  return 0;
}
