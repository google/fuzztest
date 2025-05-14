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

// This header needs to be C compatible.

#include <stddef.h>
#include <stdint.h>

// Functions defined by the fuzz testing framework.

struct FuzzTestDispatcherMutateInput {
  const void* input;
  size_t input_size;
  const void* metadata;
  size_t metadata_size;
};

struct FuzzTestDispatcherCallbacks {
  const char* (*get_binary_id)();
  void (*list_tests)();
  void (*get_seeds)();
  void (*mutate)(const struct FuzzTestDispatcherMutateInput* mutate_inputs,
                 size_t num_mutate_inputs, size_t num_mutant, int shrink);
  void (*execute)(const void* input, size_t size);
};

// Functions provided by the dispatcher library.

extern "C" int FuzzTestDispatcherIsEnabled();
extern "C" const char* FuzzTestDispatcherGetTestName();
// Ignored for now.
// extern "C" int FuzzTestDispatcherGetDeadline();
extern "C" int FuzzTestDispatcherRun(
    const struct FuzzTestDispatcherCallbacks* callbacks);

extern "C" void FuzzTestDispatcherEmitTestName(const char* name);
extern "C" void FuzzTestDispatcherEmitSeed(const void* data, size_t size);
extern "C" void FuzzTestDispatcherEmitMutant(const void* data, size_t size);
typedef uint64_t FuzzTestDispathcerCounterId;
extern "C" void FuzzTestDispatcherEmitFeedbackAs1BitCounters(
    const FuzzTestDispathcerCounterId* counter_list, size_t num_counters);
extern "C" void FuzzTestDispatcherEmitExecutionMetadata(const void* metadata,
                                                        size_t size);
enum FuzzTestDispatcherFailureType {
  kFuzzTestInputFailure = 0,
  kFuzzTestIgnoredFailure,
  kFuzzTestSetupFailure,
  kFuzzTestSkippedTest,
};
extern "C" void FuzzTestDispatcherEmitFailure(
    FuzzTestDispatcherFailureType type, const char* description,
    const void* signature, size_t signature_size);

#endif
