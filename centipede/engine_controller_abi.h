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

#ifndef FUZZTEST_CENTIPEDE_ENGINE_CONTROLLER_ABI_H_
#define FUZZTEST_CENTIPEDE_ENGINE_CONTROLLER_ABI_H_

// FuzzTest engine ABI.
//
// This header needs to be C-compatible.

#include "./centipede/engine_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  kFuzzTestControllerSuccess = 0,
  kFuzzTestControllerFailure,
} FuzzTestControllerStatus;

typedef struct {
  const FuzzTestBytesView* views;
  size_t count;
} FuzzTestBytesViews;

// Run the FuzzTest controller with `flags` and `manager`.
FuzzTestControllerStatus FuzzTestControllerRun(
    const FuzzTestAdapterManager* manager, const FuzzTestBytesViews* flags);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // FUZZTEST_CENTIPEDE_ENGINE_CONTROLLER_ABI_H_
