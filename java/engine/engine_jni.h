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

#ifndef FUZZTEST_JAVA_ENGINE_ENGINE_JNI_H_
#define FUZZTEST_JAVA_ENGINE_ENGINE_JNI_H_

#include <jni.h>

#include "./centipede/engine_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*FuzzTestJavaManagerTestCallback)(
    const FuzzTestAdapterManager* manager, void* callback_ctx);

// Builds a C `FuzzTestAdapterManager` backed by `j_manager` and invokes
// `callback(&manager, callback_ctx)` so unit tests can exercise every C ABI
// callback in-process against the loaded JNI library.
JNIEXPORT void JNICALL FuzzTestJavaRunWithManagerForTesting(
    JNIEnv* env, jobject j_manager, FuzzTestJavaManagerTestCallback callback,
    void* callback_ctx);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // FUZZTEST_JAVA_ENGINE_ENGINE_JNI_H_
