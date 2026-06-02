// Copyright 2026 The FuzzTest Authors.
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

#ifndef FUZZTEST_CENTIPEDE_ENGINE_WORKER_ABI_H_
#define FUZZTEST_CENTIPEDE_ENGINE_WORKER_ABI_H_

// FuzzTest engine worker ABI.
//
// This header needs to be C-compatible.

#include <stddef.h>
#include <stdint.h>

#include "./centipede/engine_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  kFuzzTestWorkerSuccess = 0,  // Test should finish with a success
  kFuzzTestWorkerFailure,      // Test should finish with a failure.
  kFuzzTestWorkerNotRequired,  // Test should continue with controller commands.
} FuzzTestWorkerStatus;

// Try to run as a FuzzTest worker with `manager` if needed.
FuzzTestWorkerStatus FuzzTestWorkerMaybeRun(
    const FuzzTestAdapterManager* manager);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // FUZZTEST_CENTIPEDE_ENGINE_WORKER_ABI_H_
