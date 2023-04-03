// Copyright 2022 The Centipede Authors.
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

#ifndef THIRD_PARTY_CENTIPEDE_RUNNER_INTERFACE_H_
#define THIRD_PARTY_CENTIPEDE_RUNNER_INTERFACE_H_

#include <cstddef>
#include <cstdint>

// Typedefs for the libFuzzer API, https://llvm.org/docs/LibFuzzer.html
using FuzzerTestOneInputCallback = int (*)(const uint8_t *data, size_t size);
using FuzzerInitializeCallback = int (*)(int *argc, char ***argv);
using FuzzerCustomMutatorCallback = size_t (*)(uint8_t *data, size_t size,
                                               size_t max_size,
                                               unsigned int seed);
using FuzzerCustomCrossOverCallback = size_t (*)(
    const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2,
    uint8_t *out, size_t max_out_size, unsigned int seed);

// This is the header-less interface of libFuzzer, see
// https://llvm.org/docs/LibFuzzer.html.
extern "C" {
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);
__attribute__((weak)) size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                                     size_t max_size,
                                                     unsigned int seed);
__attribute__((weak)) size_t LLVMFuzzerCustomCrossOver(
    const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2,
    uint8_t *out, size_t max_out_size, unsigned int seed);
}  // extern "C"

// The main Centipede Runner function.
// It performs actions prescribed by argc/argv and environment variables
// and returns EXIT_SUCCESS or EXIT_FAILURE.
// `test_one_input_cb` must be non-nullptr, the other callbacks may be nullptr.
// Normally, the runner itself calls this function (runner_main.cc).
//
// As an *experiment* we want to allow user code to call CentipedeRunnerMain().
// This is not a guaranteed public interface (yet) and may disappear w/o notice.
extern "C" int CentipedeRunnerMain(
    int argc, char **argv, FuzzerTestOneInputCallback test_one_input_cb,
    FuzzerInitializeCallback initialize_cb,
    FuzzerCustomMutatorCallback custom_mutator_cb,
    FuzzerCustomCrossOverCallback custom_crossover_cb);

// https://llvm.org/docs/LibFuzzer.html#using-libfuzzer-as-a-library
extern "C" int LLVMFuzzerRunDriver(
    int *argc, char ***argv, FuzzerTestOneInputCallback test_one_input_cb);

// This interface can be used to detect presence of Centipede in the binary.
// Also pretend we are LibFuzzer for compatibility.
// This API can be used by other pieces of fuzzing infrastructure,
// but should not be used by end-users of fuzz targets
// (consider using FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION macro).
extern "C" __attribute__((weak)) void CentipedeIsPresent();
extern "C" __attribute__((weak)) void __libfuzzer_is_present();

#endif  // THIRD_PARTY_CENTIPEDE_RUNNER_INTERFACE_H_
