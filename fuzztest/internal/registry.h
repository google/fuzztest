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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_REGISTRY_H_
#define FUZZTEST_FUZZTEST_INTERNAL_REGISTRY_H_

#include "absl/functional/function_ref.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/internal/registration.h"
#include "./fuzztest/internal/runtime.h"

namespace fuzztest {
namespace internal {

// Adds a fuzz test described by `test_info` and `factory` to the global
// registry, and passes the newly registered test to the current registration
// callback, if one is set (see `SetRegistrationCallback()`).
//
// Must be called before `InitFuzzTest()`.
void RegisterImpl(BasicTestInfo test_info, FuzzTestFuzzerFactory factory);

void ForEachTest(absl::FunctionRef<void(FuzzTest&)> func);

// A callback that is notified about each registered fuzz test.
using RegistrationCallback = void (*)(FuzzTest&);

// Sets the process-wide registration callback to `callback`. The callback is
// immediately invoked for every fuzz test registered so far, and then for each
// fuzz test registered afterwards by `RegisterImpl()`. Because of this replay,
// a callback set during static initialization sees every fuzz test, whatever
// the order in which translation units are initialized. Note, however, that
// tests registered before the callback is set are delivered to it in a batch
// when it is set, so their position relative to other registrations (e.g.,
// regular GoogleTest tests) depends on static-initialization order.
//
// The callback can be set only once: `callback` must not be null, setting the
// callback that is already set is a no-op (tests are not replayed again), and
// setting a different callback is a fatal error.
//
// This lets the registry stay independent of the test framework: e.g., the
// GoogleTest adaptor installs a callback that registers each fuzz test with
// GoogleTest (see `RegisterGoogleTestAdaptor()`). Not thread-safe; meant to be
// called during static initialization or before `InitFuzzTest()`.
void SetRegistrationCallback(RegistrationCallback callback);

using SetUpTearDownTestSuiteFunction = void (*)();

void RegisterSetUpTearDownTestSuiteFunctions(
    absl::string_view suite_name,
    SetUpTearDownTestSuiteFunction set_up_test_suite,
    SetUpTearDownTestSuiteFunction tear_down_test_suite);

SetUpTearDownTestSuiteFunction GetSetUpTestSuite(absl::string_view suite_name);

SetUpTearDownTestSuiteFunction GetTearDownTestSuite(
    absl::string_view suite_name);

}  // namespace internal
}  // namespace fuzztest

#endif  // FUZZTEST_FUZZTEST_INTERNAL_REGISTRY_H_
