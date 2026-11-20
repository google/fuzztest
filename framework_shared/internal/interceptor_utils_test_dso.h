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

#ifndef FUZZTEST_FRAMEWORK_SHARED_INTERNAL_INTERCEPTOR_UTILS_TEST_DSO_H_
#define FUZZTEST_FRAMEWORK_SHARED_INTERNAL_INTERCEPTOR_UTILS_TEST_DSO_H_

namespace fuzztest::internal {

// Invokes FUZZTEST_REAL(fuzztest_test_cross_dso_fn) from inside the test DSO.
int CallCrossDsoOrigFromDso(int x);

// Returns the address of __interceptor_fuzztest_test_cross_dso_fn as resolved
// from inside the test DSO.
const void* GetCrossDsoSanitizerInterceptorAddrFromDso();

// Returns the address of a function defined inside the test DSO.
const void* GetDsoCodeAddress();

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FRAMEWORK_SHARED_INTERNAL_INTERCEPTOR_UTILS_TEST_DSO_H_
