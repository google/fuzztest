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

// Coverage-tracing function interceptors for Centipede.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "absl/base/optimization.h"
#include "./centipede/interceptor_utils.h"
#include "./centipede/runner_utils.h"
#include "./centipede/sancov_state.h"

using fuzztest::internal::tls;

namespace {

// Normalize the *cmp result value to be one of {1, -1, 0}.
// According to the spec, *cmp can return any positive or negative value,
// and in fact it does return various different positive and negative values
// depending on <some random factors>. These values are later passed to our
// CMP instrumentation and are used to produce features.
// If we don't normalize the return value here, our tests may be flaky.
int NormalizeCmpResult(int result) {
  if (result < 0) return -1;
  if (result > 0) return 1;
  return result;
}

}  // namespace

namespace fuzztest::internal {
void CoverageInterceptor() {}  // to be referenced in sancov_state.cc
}  // namespace fuzztest::internal

DECLARE_CENTIPEDE_ORIG_FUNC(int, memcmp,
                            (const void *s1, const void *s2, size_t n));
DECLARE_CENTIPEDE_ORIG_FUNC(int, strcmp, (const char *s1, const char *s2));
DECLARE_CENTIPEDE_ORIG_FUNC(int, strncmp,
                            (const char *s1, const char *s2, size_t n));
DECLARE_CENTIPEDE_ORIG_FUNC(int, strcasecmp, (const char* s1, const char* s2));
DECLARE_CENTIPEDE_ORIG_FUNC(int, strncasecmp,
                            (const char* s1, const char* s2, size_t n));

// Fallback for the case *cmp_orig is null.
// Will be executed several times at process startup, if at all.
static FUZZTEST_NO_SANITIZE int memcmp_fallback(const void* s1, const void* s2,
                                                size_t n) {
  const auto *p1 = static_cast<const uint8_t *>(s1);
  const auto *p2 = static_cast<const uint8_t *>(s2);
  for (size_t i = 0; i < n; ++i) {
    int diff = p1[i] - p2[i];
    if (diff) return diff;
  }
  return 0;
}

// Fallback for case insensitive comparison.
static FUZZTEST_NO_SANITIZE int memcasecmp_fallback(const void* s1,
                                                    const void* s2, size_t n) {
  static uint8_t to_lower[256];
  [[maybe_unused]] static bool initialize_to_lower = [&] {
    for (size_t i = 0; i < sizeof(to_lower); ++i) {
      to_lower[i] = i;
      if ('A' <= to_lower[i] && to_lower[i] <= 'Z') {
        to_lower[i] = to_lower[i] - 'A' + 'a';
      }
    }
    return true;
  }();
  const auto* p1 = static_cast<const uint8_t*>(s1);
  const auto* p2 = static_cast<const uint8_t*>(s2);
  for (size_t i = 0; i < n; ++i) {
    int diff = to_lower[p1[i]] - to_lower[p2[i]];
    if (diff) return diff;
  }
  return 0;
}

// memcmp interceptor.
// Calls the real memcmp() and possibly modifies state.cmp_feature_set.
extern "C" FUZZTEST_NO_SANITIZE int memcmp(const void* s1, const void* s2,
                                           size_t n) {
  const int result =
      memcmp_orig ? memcmp_orig(s1, s2, n) : memcmp_fallback(s1, s2, n);
  if (ABSL_PREDICT_FALSE(!tls.traced)) {
    return result;
  }
  tls.TraceMemCmp(reinterpret_cast<uintptr_t>(__builtin_return_address(0)),
                  reinterpret_cast<const uint8_t *>(s1),
                  reinterpret_cast<const uint8_t *>(s2), n, result == 0);
  return NormalizeCmpResult(result);
}

// TODO(b/341111359): Investigate inefficiencies in the `strcmp`/`strncmp`
// interceptors and `TraceMemCmp`.

// strcmp interceptor.
// Calls the real strcmp() and possibly modifies state.cmp_feature_set.
extern "C" FUZZTEST_NO_SANITIZE int strcmp(const char* s1, const char* s2) {
  // Find the length of the shorter string, as this determines the actual number
  // of bytes that are compared. Note that this is needed even if we call
  // `strcmp_orig` because we're passing it to `TraceMemCmp()`.
  size_t len = 0;
  while (s1[len] && s2[len]) ++len;
  const int result =
      // Need to include one more byte than the shorter string length
      // when falling back to memcmp e.g. "foo" < "foobar".
      strcmp_orig ? strcmp_orig(s1, s2) : memcmp_fallback(s1, s2, len + 1);
  if (ABSL_PREDICT_FALSE(!tls.traced)) {
    return result;
  }
  // Pass `len` here to avoid storing the trailing '\0' in the dictionary.
  tls.TraceMemCmp(reinterpret_cast<uintptr_t>(__builtin_return_address(0)),
                  reinterpret_cast<const uint8_t *>(s1),
                  reinterpret_cast<const uint8_t *>(s2), len, result == 0);
  return NormalizeCmpResult(result);
}

// strncmp interceptor.
// Calls the real strncmp() and possibly modifies state.cmp_feature_set.
extern "C" FUZZTEST_NO_SANITIZE int strncmp(const char* s1, const char* s2,
                                            size_t n) {
  // Find the length of the shorter string, as this determines the actual number
  // of bytes that are compared. Note that this is needed even if we call
  // `strncmp_orig` because we're passing it to `TraceMemCmp()`.
  size_t len = 0;
  while (len < n && s1[len] && s2[len]) ++len;
  // Need to include '\0' in the comparison if the shorter string is shorter
  // than `n`, hence we add 1 to the length.
  if (n > len + 1) n = len + 1;
  const int result =
      strncmp_orig ? strncmp_orig(s1, s2, n) : memcmp_fallback(s1, s2, n);
  if (ABSL_PREDICT_FALSE(!tls.traced)) {
    return result;
  }
  // Pass `len` here to avoid storing the trailing '\0' in the dictionary.
  tls.TraceMemCmp(reinterpret_cast<uintptr_t>(__builtin_return_address(0)),
                  reinterpret_cast<const uint8_t *>(s1),
                  reinterpret_cast<const uint8_t *>(s2), len, result == 0);
  return NormalizeCmpResult(result);
}

// strcasecmp interceptor.
// Calls the real strcasecmp() and possibly modifies state.cmp_feature_set.
extern "C" FUZZTEST_NO_SANITIZE int strcasecmp(const char* s1, const char* s2) {
  // Find the length of the shorter string, as this determines the actual number
  // of bytes that are compared. Note that this is needed even if we call
  // `strcasecmp_orig` because we're passing it to `TraceMemCmp()`.
  size_t len = 0;
  while (s1[len] && s2[len]) ++len;
  const int result =
      // Need to include one more byte than the shorter string length
      // when falling back to memcasecmp e.g. "foo" < "foobar".
      strcasecmp_orig ? strcasecmp_orig(s1, s2)
                      : memcasecmp_fallback(s1, s2, len + 1);
  if (ABSL_PREDICT_FALSE(!tls.traced)) {
    return result;
  }
  // Pass `len` here to avoid storing the trailing '\0' in the dictionary.
  tls.TraceMemCmp(reinterpret_cast<uintptr_t>(__builtin_return_address(0)),
                  reinterpret_cast<const uint8_t*>(s1),
                  reinterpret_cast<const uint8_t*>(s2), len, result == 0);
  return NormalizeCmpResult(result);
}

// strncasecmp interceptor.
// Calls the real strncasecmp() and possibly modifies state.cmp_feature_set.
extern "C" FUZZTEST_NO_SANITIZE int strncasecmp(const char* s1, const char* s2,
                                                size_t n) {
  // Find the length of the shorter string, as this determines the actual number
  // of bytes that are compared. Note that this is needed even if we call
  // `strncasecmp_orig` because we're passing it to `TraceMemCmp()`.
  size_t len = 0;
  while (len < n && s1[len] && s2[len]) ++len;
  // Need to include '\0' in the comparison if the shorter string is shorter
  // than `n`, hence we add 1 to the length.
  if (n > len + 1) n = len + 1;
  const int result = strncasecmp_orig ? strncasecmp_orig(s1, s2, n)
                                      : memcasecmp_fallback(s1, s2, n);
  if (ABSL_PREDICT_FALSE(!tls.traced)) {
    return result;
  }
  // Pass `len` here to avoid storing the trailing '\0' in the dictionary.
  tls.TraceMemCmp(reinterpret_cast<uintptr_t>(__builtin_return_address(0)),
                  reinterpret_cast<const uint8_t*>(s1),
                  reinterpret_cast<const uint8_t*>(s2), len, result == 0);
  return NormalizeCmpResult(result);
}
