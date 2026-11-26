// Copyright 2025 The Centipede Authors.
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

#ifndef FUZZTEST_FRAMEWORK_SHARED_SANCOV_RUNTIME_H_
#define FUZZTEST_FRAMEWORK_SHARED_SANCOV_RUNTIME_H_

// Sancov runtime interface.
//
// This header needs to be C compatible.

#include <stdbool.h>  // NOLINT
#include <stddef.h>
#include <stdint.h>

#include "./centipede/engine_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

struct SanCovRuntimeRawFeatureParts {
  const uint64_t* features;
  size_t num_features;
};

// Callback invoked when the observed stack usage of a thread increases or
// during coverage post-processing. `is_current_stack` is true when called
// synchronously on the thread whose stack grew, and false when called during
// post-processing for a thread's recorded stack usage.
typedef void (*SanCovRuntimeStackLimitCallback)(size_t stack_usage,
                                                bool is_current_stack);

// An overridable hook to get the SanCov runtime flags during initialization.
// The default weak implementation reads the `CENTIPEDE_RUNNER_FLAGS`
// environment variable.
//
// Should return either NULL or a constant string valid for the lifetime of the
// process. Multiple calls should always return the same value.
const char* GetSancovFlags(void);

// Initializes the SanCov runtime. Can be called multiple times; only the first
// call takes effect. Call this before using the runtime during static
// initialization (when initialization order across translation units is
// unspecified).
void SanCovRuntimeInitialize(void);

// Registers a callback for checking stack usage limits, or clears it when
// `callback` is NULL.
void SanCovRuntimeSetStackLimitCallback(
    SanCovRuntimeStackLimitCallback callback);

// Enables (if `traced` is true) or disables (if `traced` is false) SanCov
// feedback tracing on the current thread. Returns the previous `traced` value.
bool SanCovRuntimeSetCurrentThreadTraced(bool traced);

// Sets whether the current thread is ignored when iterating thread-local
// SanCov states (e.g., for internal helper threads that do not execute user
// code).
void SanCovRuntimeSetCurrentThreadIgnored(bool ignored);

// Clears coverage data accumulated so far from sancov callbacks and/or
// interceptors.
//
// Will always clear the thread-local data updated during execution, and if
// `full_clear==true` will clear all accumulated coverage data.
void SanCovRuntimeClearCoverage(bool full_clear);

// Post-processes all coverage data, putting it all into an array of features,
// and returning a ptr and the length of this array.
//
// Will return a valid `features` pointer to a 64-bit element array of length
// `num_features`: This feature array is initialized at process startup, and
// its data (belonging to a global state) will remain valid for the duration of
// the process.
//
// If `reject_input==true`, then it will simply empty the feature array.
//
// DEPRECATED: the features here is in the raw Centipede layout instead of
// the standard engine layout. Use `SanCovRuntimePostProcessCoverage` +
// `SanCovRuntimeEmitFeatures` to work with the engine.
struct SanCovRuntimeRawFeatureParts SanCovRuntimeGetCoverage(bool reject_input);

// Returns the post-processed features in the raw Centipede layout from the
// most recent `SanCovRuntimePostProcessCoverage` call.
//
// DEPRECATED: the features here are in the raw Centipede layout instead of
// the standard engine layout. Use `SanCovRuntimePostProcessCoverage` +
// `SanCovRuntimeEmitFeatures` to work with the engine.
struct SanCovRuntimeRawFeatureParts SanCovRuntimeGetRawFeatures(void);

// Converts raw Centipede features in `[features, features + num_features)`
// in-place to the engine feature layout defined in `engine_abi.h`.
//
// DEPRECATED: only needed for legacy `CentipedeSetExecutionResult` support.
void SanCovRuntimeConvertToEngineFeatures(uint64_t* features,
                                          size_t num_features);

// Returns the serialized CMP metadata gathered by the most recent
// `SanCovRuntimePostProcessCoverage` call, as packed entries of the form
// `[size: uint8_t][value0: size bytes][value1: size bytes]...`. The returned
// view remains valid until the next `SanCovRuntimePostProcessCoverage` call.
FuzzTestBytesView SanCovRuntimeGetCmpData(void);

// Registers the SanCov coverage domains. Returns next available domain ID.
size_t SanCovRuntimeSetUpCoverageDomains(
    const FuzzTestCoverageDomainRegistry* registry);

// Post-processes all coverage data, and saves it internally for later emission
// and retrieval.
//
// If `reject_input==true`, no coverage would be saved.
void SanCovRuntimePostProcessCoverage(bool reject_input);

// Emits post-processed SanCov coverage features into the engine `sink`.
//
// Should be called at most once after `SanCovRuntimePostProcessCoverage` -
// later calls will emit empty coverage.
void SanCovRuntimeEmitFeatures(const FuzzTestFeedbackSink* sink);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // FUZZTEST_FRAMEWORK_SHARED_SANCOV_RUNTIME_H_
