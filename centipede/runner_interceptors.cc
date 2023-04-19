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

// Function interceptors for Centipede.
// Interceptors are disabled under ASAN/TSAN/MSAN because those sanitizers
// have their own conflicting interceptors.
// The typical usage of sanitizers with Centipede is via the --extra_binaries
// flag, where the sanitized binary does not produce coverage output and thus
// doesn't need (most of?) interceptors.
#if !defined(ADDRESS_SANITIZER) && !defined(THREAD_SANITIZER) && \
    !defined(MEMORY_SANITIZER)
#include <dlfcn.h>  // for dlsym()
#include <pthread.h>

#include <cstdint>
#include <cstring>

#include "./centipede/runner.h"

using centipede::state;
using centipede::tls;

namespace {

// Wrapper for dlsym().
// Returns the pointer to the real function `function_name`.
// In most cases we need FuncAddr("foo") to be called before the first call to
// foo(), which means we either need to do this very early at startup
// (e.g. pre-init array), or on the first call.
// Currently, we do this on the first call via function-scope static.
template <typename FunctionT>
FunctionT FuncAddr(const char *function_name) {
  void *addr = dlsym(RTLD_NEXT, function_name);
  return reinterpret_cast<FunctionT>(addr);
}

// 3rd and 4th arguments to pthread_create(), packed into a struct.
struct ThreadCreateArgs {
  void *(*start_routine)(void *);
  void *arg;
};

// Wrapper for a `start_routine` argument of pthread_create().
// Calls the actual start_routine and returns its results.
// Performs custom actions before and after start_routine().
// `arg` is a `ThreadCreateArgs *` with the actual pthread_create() args.
void *MyThreadStart(void *arg) {
  auto *args = static_cast<ThreadCreateArgs *>(arg);
  tls.OnThreadStart();
  void *retval = args->start_routine(args->arg);
  tls.OnThreadStop();
  delete args;  // allocated in the pthread_create wrapper.
  return retval;
}

}  // namespace

// Initialize memcmp_orig at the module startup. This may still be too late,
// since memcmp may be used before this module is initialized.
// So, the interceptor may not assume that memcmp_orig != nullptr.
static auto memcmp_orig =
    FuncAddr<int (*)(const void *s1, const void *s2, size_t n)>("memcmp");

// Fallback for the case memcmp_orig is null.
// Will be executed several times at process startup, if at all.
static int memcmp_fallback(const void *s1, const void *s2, size_t n) {
  const auto *p1 = static_cast<const uint8_t *>(s1);
  const auto *p2 = static_cast<const uint8_t *>(s2);
  for (size_t i = 0; i < n; ++i) {
    int diff = p1[i] - p2[i];
    if (diff) return diff;
  }
  return 0;
}

// memcmp interceptor.
// Calls the real memcmp() and possibly modifies state.cmp_feature_set.
extern "C" int memcmp(const void *s1, const void *s2, size_t n) {
  uint64_t a = 0, b = 0;
  if (n <= sizeof(a) && state.run_time_flags.use_cmp_features) {
    memcpy(&a, s1, n);
    memcpy(&b, s2, n);
    auto caller_pc = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    uintptr_t pc_offset = caller_pc - state.main_object.start_address;
    uintptr_t hash =
        centipede::Hash64Bits(pc_offset) ^ tls.path_ring_buffer.hash();
    state.cmp_feature_set.set(
        centipede::ConvertContextAndArgPairToNumber(a, b, hash));
  }
  int result =
      memcmp_orig ? memcmp_orig(s1, s2, n) : memcmp_fallback(s1, s2, n);
  if (result != 0 && state.run_time_flags.use_auto_dictionary) {
    tls.cmp_traceN.Capture(n, reinterpret_cast<const uint8_t *>(s1),
                           reinterpret_cast<const uint8_t *>(s2));
  }
  return result;
}

// pthread_create interceptor.
// Calls real pthread_create, but wraps the start_routine() in MyThreadStart.
extern "C" int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                              void *(*start_routine)(void *), void *arg) {
  static auto pthread_create_orig =
      FuncAddr<int (*)(pthread_t *, const pthread_attr_t *, void *(*)(void *),
                       void *)>("pthread_create");
  // Wrap the arguments. Will be deleted in MyThreadStart.
  auto *wrapped_args = new ThreadCreateArgs{start_routine, arg};
  // Run the actual pthread_create.
  return pthread_create_orig(thread, attr, MyThreadStart, wrapped_args);
}
#endif  // not ASAN/TSAN/MSAN
