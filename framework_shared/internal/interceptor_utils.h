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

#ifndef FUZZTEST_FRAMEWORK_SHARED_INTERNAL_INTERCEPTOR_UTILS_H_
#define FUZZTEST_FRAMEWORK_SHARED_INTERNAL_INTERCEPTOR_UTILS_H_

#include <dlfcn.h>  // for dladdr(), dlsym()

namespace fuzztest::internal {

// Wrapper for dlsym().
// Returns the pointer to the real function `function_name`.
// Marked always_inline so RTLD_NEXT resolves relative to the calling shared
// object rather than an interposed out-of-line instantiation.
template <typename FunctionT>
__attribute__((always_inline)) inline FunctionT FuncAddr(
    const char* function_name) {
  void* addr = dlsym(RTLD_NEXT, function_name);
  return reinterpret_cast<FunctionT>(addr);
}

// Returns true if `addr1` and `addr2` belong to the same loaded binary or
// shared object.
inline bool InSameSharedObject(const void* addr1, const void* addr2) {
  Dl_info info1 = {};
  Dl_info info2 = {};
  return dladdr(addr1, &info1) != 0 && dladdr(addr2, &info2) != 0 &&
         info1.dli_fbase == info2.dli_fbase;
}

}  // namespace fuzztest::internal

// A sanitizer-compatible way to intercept functions that are potentially
// intercepted by sanitizers, in which case the symbol __interceptor_X would be
// defined for intercepted function X.
//
// When our interceptor is linked into the same binary/DSO as the sanitizer
// runtime, our strong definition of X overrides the sanitizer's weak alias, so
// RTLD_NEXT would skip the sanitizer; we therefore forward directly to
// __interceptor_X. When our interceptor lives in a separate DSO (e.g. via
// LD_PRELOAD), the dynamic linker's RTLD_NEXT chain already orders the two
// interceptors without looping, whereas jumping back to __interceptor_X in an
// earlier DSO would cause infinite recursion.
//
// We define the fuzztest_X_orig pointers that are statically initialized to
// FuzzTestGetOrig_X() with the aforementioned logic to fill the pointers early,
// but they might still be too late. So the Centipede interceptors might need to
// handle the nullptr case and/or use FUZZTEST_REAL(X), which calls
// FuzzTestGetOrig_X() when needed. Also see
// compiler-rt/lib/interception/interception.h in the llvm-project source code.
//
// Note that since LLVM 17 it allows three interceptions (from the original
// binary, an external tool, and a sanitizer) to co-exist under a new scheme,
// while it is still compatible with the old way used here.
#define FUZZTEST_SANITIZER_INTERCEPTOR_NAME(orig_func_name) \
  __interceptor_##orig_func_name
#define FUZZTEST_DECLARE_ORIG_FUNC(ret_type, orig_func_name, args)         \
  extern "C" __attribute__((weak)) ret_type(                               \
      FUZZTEST_SANITIZER_INTERCEPTOR_NAME(orig_func_name)) args;           \
  static decltype(&FUZZTEST_SANITIZER_INTERCEPTOR_NAME(orig_func_name))    \
  FuzzTestGetOrig_##orig_func_name() {                                     \
    if (auto sanitizer_interceptor =                                       \
            &FUZZTEST_SANITIZER_INTERCEPTOR_NAME(orig_func_name);          \
        sanitizer_interceptor != nullptr &&                                \
        ::fuzztest::internal::InSameSharedObject(                          \
            reinterpret_cast<const void*>(sanitizer_interceptor),          \
            reinterpret_cast<const void*>(                                 \
                &FuzzTestGetOrig_##orig_func_name))) {                     \
      return sanitizer_interceptor;                                        \
    }                                                                      \
    return ::fuzztest::internal::FuncAddr<                                 \
        decltype(&FUZZTEST_SANITIZER_INTERCEPTOR_NAME(orig_func_name))>(   \
        #orig_func_name);                                                  \
  }                                                                        \
  static ret_type(*fuzztest_##orig_func_name##_orig) args;                 \
  static __attribute__((constructor)) void                                 \
  FuzzTestInitializeOrig_##orig_func_name() {                              \
    fuzztest_##orig_func_name##_orig = FuzzTestGetOrig_##orig_func_name(); \
  }
#define FUZZTEST_REAL(orig_func_name)                                  \
  (fuzztest_##orig_func_name##_orig ? fuzztest_##orig_func_name##_orig \
                                    : FuzzTestGetOrig_##orig_func_name())

#endif  // FUZZTEST_FRAMEWORK_SHARED_INTERNAL_INTERCEPTOR_UTILS_H_
