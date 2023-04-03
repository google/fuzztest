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

// Centipede puzzle: stress test for --use_auto_dictionary=1.
// RUN: Run --use_auto_dictionary=1 --use_cmp_features=0 -j 5
// RUN: ExpectInLog "Input bytes.*: abcdxyzVeryLongString"

// TODO(kcc): we currently use --use_cmp_features=0 because otherwise
// the corpus gets too large and the puzzle does not get solved quickly.
// Ideally, we should be able to run this puzzle w/o --use_cmp_features=0.

#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  auto beg = data;
  auto end = data + size;

  auto cmp_and_forward = [&](const char *str) {
    auto len = strlen(str);
    if (end - beg >= len && memcmp(beg, str, len) == 0) {
      beg += len;
      return true;
    }
    return false;
  };

  if (cmp_and_forward("abcd") && cmp_and_forward("xyz") &&
      cmp_and_forward("VeryLongString")) {
    abort();
  }

  return 0;
}
