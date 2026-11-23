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

#include "./framework_shared/internal/interceptor_utils_test_dso.h"

#include "./framework_shared/internal/interceptor_utils.h"
#include "./framework_shared/internal/interceptor_utils_test_target_dso.h"

FUZZTEST_DECLARE_ORIG_FUNC(int, fuzztest_test_cross_dso_fn, (int));

extern "C" __attribute__((visibility("default"))) int
fuzztest_test_cross_dso_fn(int x) {
  return FUZZTEST_REAL(fuzztest_test_cross_dso_fn)(x) + 10;
}

namespace fuzztest::internal {

int CallCrossDsoOrigFromDso(int x) {
  // Reference the target DSO so --as-needed keeps its DT_NEEDED edge.
  if (InterceptorUtilsTestTargetDsoMarker() == 0) return -1;
  return FUZZTEST_REAL(fuzztest_test_cross_dso_fn)(x);
}

const void* GetCrossDsoSanitizerInterceptorAddrFromDso() {
  return reinterpret_cast<const void*>(
      &FUZZTEST_SANITIZER_INTERCEPTOR_NAME(fuzztest_test_cross_dso_fn));
}

const void* GetDsoCodeAddress() {
  return reinterpret_cast<const void*>(&CallCrossDsoOrigFromDso);
}

}  // namespace fuzztest::internal
