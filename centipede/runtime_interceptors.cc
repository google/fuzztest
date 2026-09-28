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

// Runtime function interceptors for Centipede.

#include <pthread.h>

#include "absl/base/nullability.h"
#include "absl/base/optimization.h"
#include "./centipede/interceptor_utils.h"
#include "./centipede/sancov_state.h"

using fuzztest::internal::tls;

namespace {

// 3rd and 4th arguments to pthread_create(), packed into a struct.
struct ThreadCreateArgs {
  void *(*start_routine)(void *);
  void *arg;
};

// Wrapper for a `start_routine` argument of pthread_create().
// Calls the actual start_routine and returns its results.
// Performs custom actions before and after start_routine().
// `arg` is a `ThreadCreateArgs *` with the actual pthread_create() args.
void *MyThreadStart(void *absl_nonnull arg) {
  auto *args_orig_ptr = static_cast<ThreadCreateArgs *>(arg);
  auto args = *args_orig_ptr;
  delete args_orig_ptr;  // allocated in the pthread_create wrapper.
  tls.OnThreadStart();
  void *retval = args.start_routine(args.arg);
  return retval;
}

}  // namespace

namespace fuzztest::internal {
void RuntimeInterceptor() {}  // to be referenced in sancov_state.cc
}  // namespace fuzztest::internal

FUZZTEST_DECLARE_ORIG_FUNC(int, pthread_create,
                           (pthread_t * thread, const pthread_attr_t* attr,
                            void* (*start_routine)(void*), void* arg));

// pthread_create interceptor.
// Calls real pthread_create, but wraps the start_routine() in MyThreadStart.
extern "C" int pthread_create(
    pthread_t *absl_nonnull thread,            // NOLINT
    const pthread_attr_t *absl_nullable attr,  // NOLINT
    void *(*start_routine)(void *),
    void *absl_nullable arg) {  // NOLINT
  if (ABSL_PREDICT_FALSE(!tls.started)) {
    return FUZZTEST_REAL(pthread_create)(thread, attr, start_routine, arg);
  }
  // Wrap the arguments. Will be deleted in MyThreadStart.
  auto *wrapped_args = new ThreadCreateArgs{start_routine, arg};
  // Run the actual pthread_create.
  return FUZZTEST_REAL(pthread_create)(thread, attr, MyThreadStart,
                                       wrapped_args);
}
