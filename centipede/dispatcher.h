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

#ifndef THIRD_PARTY_CENTIPEDE_DISPATCHER_H_
#define THIRD_PARTY_CENTIPEDE_DISPATCHER_H_

// Dispatcher interface.
//
// This header needs to be C compatible.

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Inputs to perform mutations.
struct FuzzTestDispatcherMutateInput {
  const void* input;
  size_t input_size;
  const void* metadata;
  size_t metadata_size;
};

// Callbacks to be provided by the fuzz testing framework to
// `FuzzTestDispatcherRun`.
struct FuzzTestDispatcherCallbacks {
  // Optional callback to return a ID for the current binary.
  const char* (*get_binary_id)();
  // Callback to emit the list of available tests.
  void (*list_tests)();
  // Callback to emit the seed inputs for a test.
  void (*get_seeds)();
  // Callback to emit at most `num_mutants` from `mutate_inputs` with
  // `num_mutate_inputs` entires. `shrink` != 0 means to generate smaller
  // mutatns than the inputs used for mutation.
  void (*mutate)(const struct FuzzTestDispatcherMutateInput* mutate_inputs,
                 size_t num_mutate_inputs, size_t num_mutants, int shrink);
  // Callback to execute `input` with `size` bytes.
  void (*execute)(const void* input, size_t size);
};

// Functions provided by the FuzzTest engine.

// Returns 0 if the dispatcher mode is not enabled in the current process; 1 if
// the dispatcher mode is enabled; other values for unexpected errors.
int FuzzTestDispatcherIsEnabled();

// All functions below should be called only after `FuzzTestDispatcherIsEnabled`
// returns 1 in the current process.

// Returns the test name under operation as an unowned, static, and
// null-terminated string. Returns nullptr if the current process is not
// operating on a specific test.
const char* FuzzTestDispatcherGetTestName();
// Give control to the FuzzTest engine to invoke `callbacks`. Returns an exit
// code for the current process desired by the engine.
int FuzzTestDispatcherRun(const struct FuzzTestDispatcherCallbacks* callbacks);
// Emits a test name. Must be called from the `list_tests` callback.
void FuzzTestDispatcherEmitTestName(const char* name);
// Emits a seed input. Must be called from the `get_seeds` callback.
void FuzzTestDispatcherEmitSeed(const void* data, size_t size);
// Emits a mutant. Must be called from the `mutate` callback.
void FuzzTestDispatcherEmitMutant(const void* data, size_t size);
// Emits coverage feedback for the current input as an array of 32-bit features.
//
// For each 32-bit feature, the bit [31] is ignored; the 4 bits [30-27]
// indicate the feature domain for engine prioritization. The remaining 27 bits
// [26-0] represent the actual 27-bit feature ID in the domain.
//
// Must be called from the `execute` callback.
void FuzzTestDispatcherEmitFeedbackAs32BitFeatures(const uint32_t* features,
                                                   size_t num_features);
// Emits metadata of the current input as an raw bytes. Must be called from the
// `execute` callback.
void FuzzTestDispatcherEmitExecutionMetadata(const void* metadata, size_t size);
// Failure types to provide to engine.
enum FuzzTestDispatcherFailureType {
  // Failure caused by executing an input.
  kFuzzTestInputFailure = 0,
  // Failure that should be ignored.
  kFuzzTestIgnoredFailure,
  // Failure caused by the test setup.
  kFuzzTestSetupFailure,
  // Failures indicating that the current test should be entirely skipped.
  kFuzzTestSkippedTest,
};

// Emits failure information with `type`, `description` (as a null-terminated
// string), `signature` with `signature_size` bytes. Can be called anywhere
// except for when `type` is `kFuzzTestInputFailure`, which should be within the
// `execute` callback.
//
// Note that after calling this function, the current process should exit after
// necessary cleanup. Later calls of the function have no effect after the first
// call.
void FuzzTestDispatcherEmitFailure(enum FuzzTestDispatcherFailureType type,
                                   const char* description,
                                   const void* signature,
                                   size_t signature_size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
