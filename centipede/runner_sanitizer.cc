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

// Instrumentation callbacks for sanitizers. See
// compiler-rt/include/sanitizer/common_interface_defs.h in the LLVM
// repo.

#include <cstddef>
#include <cstdint>

#include "./centipede/runner.h"

#define NO_SANITIZE __attribute__((no_sanitize("all")))

namespace centipede {
void RunnerSanitizer() {}  // to be referenced in runner.cc
}  // namespace centipede

NO_SANITIZE
extern "C" void __sanitizer_weak_hook_memcmp(void *caller_pc, const void *s1,
                                             const void *s2, size_t n,
                                             int result) {
  if (s1 == nullptr || s2 == nullptr) return;
  centipede::tls.TraceMemCmp(reinterpret_cast<uintptr_t>(caller_pc),
                             reinterpret_cast<const uint8_t *>(s1),
                             reinterpret_cast<const uint8_t *>(s2), n,
                             result == 0);
}
NO_SANITIZE
extern "C" void __sanitizer_weak_hook_strcmp(void *caller_pc, const char *s1,
                                             const char *s2, int result) {
  if (s1 == nullptr || s2 == nullptr) return;
  size_t len = 0;
  while (s1[len] && s2[len]) ++len;
  centipede::tls.TraceMemCmp(reinterpret_cast<uintptr_t>(caller_pc),
                             reinterpret_cast<const uint8_t *>(s1),
                             reinterpret_cast<const uint8_t *>(s2), len,
                             result == 0);
}
