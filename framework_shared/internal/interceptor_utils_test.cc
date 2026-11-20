// Copyright 2026 Google LLC
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

#include "./framework_shared/internal/interceptor_utils.h"

#include <dlfcn.h>

#include "gtest/gtest.h"
#include "./framework_shared/internal/interceptor_utils_test_dso.h"

// Simulates a sanitizer interceptor linked into the same binary as
// FUZZTEST_DECLARE_ORIG_FUNC. Declare via the macro first so its weak
// attribute precedes the definition.
FUZZTEST_DECLARE_ORIG_FUNC(int, fuzztest_test_same_dso_fn, (int));

extern "C" __attribute__((visibility("default"))) int
__interceptor_fuzztest_test_same_dso_fn(int x) {
  return x + 100;
}

// Simulates a function with no sanitizer interceptor defined anywhere.
FUZZTEST_DECLARE_ORIG_FUNC(int, fuzztest_test_no_sanitizer_fn, (int));

// Simulates a sanitizer runtime in the main executable whose REAL lookup
// resolves via RTLD_NEXT to the interceptor in a separately loaded DSO.
// If the DSO mistakenly chains back to __interceptor_fuzztest_test_cross_dso_fn
// in the main executable, this would infinitely recurse (caught here via
// `recursion_depth`).
extern "C" __attribute__((visibility("default"))) int
__interceptor_fuzztest_test_cross_dso_fn(int x) {
  static int recursion_depth = 0;
  if (++recursion_depth > 1) {
    --recursion_depth;
    return -999;
  }
  using FnType = int (*)(int);
  auto next =
      reinterpret_cast<FnType>(dlsym(RTLD_NEXT, "fuzztest_test_cross_dso_fn"));
  const int result = next != nullptr ? next(x) + 100 : -1;
  --recursion_depth;
  return result;
}

extern "C" __attribute__((visibility("default"))) int
fuzztest_test_cross_dso_fn(int x) {
  return __interceptor_fuzztest_test_cross_dso_fn(x);
}

namespace fuzztest::internal {
namespace {

void SameObjectMarkerA() {}
void SameObjectMarkerB() {}

TEST(InterceptorUtilsTest, InSameSharedObjectDistinguishesMainAndDso) {
  EXPECT_TRUE(
      InSameSharedObject(reinterpret_cast<const void*>(&SameObjectMarkerA),
                         reinterpret_cast<const void*>(&SameObjectMarkerB)));
  EXPECT_FALSE(InSameSharedObject(
      reinterpret_cast<const void*>(&SameObjectMarkerA), GetDsoCodeAddress()));
}

TEST(InterceptorUtilsTest, SameSharedObjectUsesSanitizerInterceptor) {
  EXPECT_EQ(FUZZTEST_REAL(fuzztest_test_same_dso_fn)(5), 105);
}

TEST(InterceptorUtilsTest, NoSanitizerInterceptorFallsBackToRtldNext) {
  EXPECT_EQ(FUZZTEST_REAL(fuzztest_test_no_sanitizer_fn)(5), 12);
}

TEST(InterceptorUtilsTest, SeparateDsoUsesRtldNextInsteadOfRecursingIntoMain) {
  // Confirm the DSO genuinely sees the main binary's __interceptor_* symbol
  // (the precondition that previously caused mutual recursion).
  EXPECT_EQ(
      GetCrossDsoSanitizerInterceptorAddrFromDso(),
      reinterpret_cast<const void*>(&__interceptor_fuzztest_test_cross_dso_fn));

  // Inside the DSO, FUZZTEST_REAL must skip main's __interceptor_* and call
  // the next library in RTLD_NEXT order (+1), not recurse into main.
  EXPECT_EQ(CallCrossDsoOrigFromDso(5), 6);

  // Full chain: main sanitizer (+100) -> DSO interceptor (+10) -> target (+1).
  EXPECT_EQ(fuzztest_test_cross_dso_fn(5), 116);
}

}  // namespace
}  // namespace fuzztest::internal
