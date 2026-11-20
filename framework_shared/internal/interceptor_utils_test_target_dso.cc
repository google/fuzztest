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

#include "./framework_shared/internal/interceptor_utils_test_target_dso.h"

extern "C" {

// Simulates a real underlying libc function loaded after the interceptor DSO.
__attribute__((visibility("default"))) int fuzztest_test_cross_dso_fn(int x) {
  return x + 1;
}

// Simulates a real underlying function with no sanitizer interceptor defined.
__attribute__((visibility("default"))) int fuzztest_test_no_sanitizer_fn(
    int x) {
  return x + 7;
}

}  // extern "C"

namespace fuzztest::internal {

int InterceptorUtilsTestTargetDsoMarker() { return 1; }

}  // namespace fuzztest::internal
