// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef FUZZTEST_FUZZTEST_FUZZTEST_H_
#define FUZZTEST_FUZZTEST_FUZZTEST_H_

// IWYU pragma: begin_exports
#include "./fuzztest/domain.h"
#include "./fuzztest/fuzztest_macros.h"
// `fuzztest.h` is the GoogleTest-integrated entry point. (`fuzztest_macros.h`
// and the registry do not depend on GoogleTest; use them directly to avoid
// GoogleTest.) This include is necessary for two reasons:
//
// 1. It is what links the GoogleTest adaptor into the binary. The registry no
//    longer refers to the adaptor, and CMake has no equivalent of Bazel's
//    `alwayslink`. Without this include, the adaptor would be dropped at link
//    time and `FUZZ_TEST`s would silently never be registered with GoogleTest,
//    e.g., in binaries that don't call `InitFuzzTest()`, which must fail
//    loudly instead.
// 2. It keeps fuzz tests in source order. `kGoogleTestAdaptorRegistered` is an
//    `inline` variable defined before any `FUZZ_TEST` in the including file,
//    so it is initialized first, and each `FUZZ_TEST` is added to GoogleTest
//    as soon as it is registered, interleaved with the file's `TEST`s.
#include "./fuzztest/internal/googletest_adaptor.h"
// IWYU pragma: end_exports

#endif  // FUZZTEST_FUZZTEST_FUZZTEST_H_
