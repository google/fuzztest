// Copyright 2026 The Centipede Authors.
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

#ifndef FUZZTEST_CENTIPEDE_INTERCEPTOR_UTILS_H_
#define FUZZTEST_CENTIPEDE_INTERCEPTOR_UTILS_H_

#include <dlfcn.h>  // for dlsym()

namespace fuzztest::internal {

// Wrapper for dlsym().
// Returns the pointer to the real function `function_name`.
// In most cases we need FuncAddr("foo") to be called before the first call to
// foo(), which means we either need to do this very early at startup
// (e.g. pre-init array), or on the first call.
// Currently, we do this on the first call via function-scope static.
template <typename FunctionT>
FunctionT FuncAddr(const char* function_name) {
  void* addr = dlsym(RTLD_NEXT, function_name);
  return reinterpret_cast<FunctionT>(addr);
}

}  // namespace fuzztest::internal

// A sanitizer-compatible way to intercept functions that are potentially
// intercepted by sanitizers, in which case the symbol __interceptor_X would be
// defined for intercepted function X. So we always forward an intercepted call
// to the sanitizer interceptor if it exists, and fall back to the next
// definition following dlsym.
//
// We define the X_orig pointers that are statically initialized to GetOrig_X()
// with the aforementioned logic to fill the pointers early, but they might
// still be too late. So the Centipede interceptors might need to handle the
// nullptr case and/or use FUZZTEST_REAL(X), which calls GetOrig_X() when
// needed. Also see compiler-rt/lib/interception/interception.h in the
// llvm-project source code.
//
// Note that since LLVM 17 it allows three interceptions (from the original
// binary, an external tool, and a sanitizer) to co-exist under a new scheme,
// while it is still compatible with the old way used here.
#define FUZZTEST_SANITIZER_INTERCEPTOR_NAME(orig_func_name) \
  __interceptor_##orig_func_name
#define FUZZTEST_DECLARE_ORIG_FUNC(ret_type, orig_func_name, args)       \
  extern "C" __attribute__((weak)) ret_type(                             \
      FUZZTEST_SANITIZER_INTERCEPTOR_NAME(orig_func_name)) args;         \
  static decltype(&FUZZTEST_SANITIZER_INTERCEPTOR_NAME(orig_func_name))  \
  GetOrig_##orig_func_name() {                                           \
    if (auto p = &FUZZTEST_SANITIZER_INTERCEPTOR_NAME(orig_func_name))   \
      return p;                                                          \
    return ::fuzztest::internal::FuncAddr<                               \
        decltype(&FUZZTEST_SANITIZER_INTERCEPTOR_NAME(orig_func_name))>( \
        #orig_func_name);                                                \
  }                                                                      \
  static ret_type(*orig_func_name##_orig) args;                          \
  __attribute__((constructor)) void InitializeOrig_##orig_func_name() {  \
    orig_func_name##_orig = GetOrig_##orig_func_name();                  \
  }
#define FUZZTEST_REAL(orig_func_name) \
  (orig_func_name##_orig ? orig_func_name##_orig : GetOrig_##orig_func_name())

#endif  // FUZZTEST_CENTIPEDE_INTERCEPTOR_UTILS_H_
