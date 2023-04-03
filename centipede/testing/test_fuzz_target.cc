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

// A fuzz target used for testing Centipede.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <utility>

// Function with a single coverage edge. Used by coverage_test.cc.
__attribute__((noinline)) extern "C" void SingleEdgeFunc() {
  [[maybe_unused]] static volatile int sink;
  sink = 0;
}

// Function with multiple coverage edges. Used by coverage_test.cc.
__attribute__((noinline)) extern "C" void MultiEdgeFunc(uint8_t input) {
  static volatile int sink;
  if (input) {
    sink = 42;
  } else {
    sink++;
  }
}

// Function with indirect call based on the input value.
__attribute__((noinline)) extern "C" void IndirectCallFunc(uint8_t input) {
    [[maybe_unused]] static volatile int sink;
    using func_type = void (*)();
    func_type funcs[4] = {[]() { sink = 0; }, []() { sink = 1; },
                          []() { sink = 2; }, []() { sink = 3; }};
    funcs[input % 4]();
}

// Used to test data flow instrumentation.
static int non_cost_global[10];
static const int const_global[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

// See https://llvm.org/docs/LibFuzzer.html#fuzz-target.
// coverage_test.cc and centipede_test.sh verify the exact line where
// LLVMFuzzerTestOneInput is declared.
// So if you move the declaration to another line, update these tests.
//
// This test does not use memcmp or similar to keep
// the generated code very simple.
static volatile void *ptr_sink = nullptr;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Print the input. It will be tested in runner_test.
  printf("{");
  for (size_t i = 0; i < size; i++) {
    // This loop generates different coverage counters
    // depending on the number of iterations.
    printf("%02x%s", (int)data[i], i + 1 == size ? "" : ", ");
  }
  printf("}\n");

  // If the input is 'cntX', run X iterations of a do-while loop.
  // Runs one iteration if X is 0. Used to test --use_counter_features.
  if (size == 4 && data[0] == 'c' && data[1] == 'n' && data[2] == 't') {
    [[maybe_unused]] static volatile int sink;
    int num_iterations = data[3];
    // We use do-while loop to simplify the control flow here.
    do {
      sink = --num_iterations;
    } while (num_iterations >= 0);
    return 0;
  }

  // Allocate 4Gb of RAM if the input is 'oom'.
  // runner_test provokes OOM by feeding 'oom' input here,
  // and checks that we can detect the OOM with ulimit.
  if (size == 3 && data[0] == 'o' && data[1] == 'o' && data[2] == 'm') {
    size_t oom_allocation_size = 1ULL << 32;
    void *ptr = malloc(oom_allocation_size);
    memset(ptr, 42, oom_allocation_size);
    ptr_sink = ptr;
  }

  // Sleep for 10 seconds if the input is 'slo'.
  if (size == 3 && data[0] == 's' && data[1] == 'l' && data[2] == 'o') {
    sleep(10);
  }

  // Call SingleEdgeFunc() if input is "func1".
  if (size == 5 && data[0] == 'f' && data[1] == 'u' && data[2] == 'n' &&
      data[3] == 'c' && data[4] == '1') {
    SingleEdgeFunc();
  }
  // Call MultiEdgeFunc(data[6]) if input is "func2-?" ('?' is any symbol).
  if (size == 7 && data[0] == 'f' && data[1] == 'u' && data[2] == 'n' &&
      data[3] == 'c' && data[4] == '2' && data[5] == '-') {
    MultiEdgeFunc(data[6]);
  }

  // Load from `non_cost_global` if input is "glob[0-9]".
  // The last digit is the index into non_cost_global.
  if (size == 5 && data[0] == 'g' && data[1] == 'l' && data[2] == 'o' &&
      data[3] == 'b' && data[4] >= '0' && data[4] <= '9') {
    size_t offset = data[4] - '0';
    [[maybe_unused]] static volatile int sink;
    printf("loading from %p at offset %zd\n", &non_cost_global, offset);
    sink = non_cost_global[offset];
  }

  // Load from `cost_global` if input is "cons[0-9]".
  // The last digit is the index into cost_global.
  // Keep the inputs for glob[0-9] (above) and cons[0-9] (here) the same length,
  // so that it takes the same amount of work for a fuzzer to discover.
  if (size == 5 && data[0] == 'c' && data[1] == 'o' && data[2] == 'n' &&
      data[3] == 's' && data[4] >= '0' && data[4] <= '9') {
    size_t offset = data[4] - '0';
    [[maybe_unused]] static volatile int sink;
    printf("loading from %p at offset %zd\n", &const_global, offset);
    sink = const_global[offset];
  }

  // If input is "cmpABCDEFGH" (A-H - any bytes), execute a comparison
  // instruction between ABCD and EFGH (treated as uint32_t).
  if (size == 3 + 4 + 4 && data[0] == 'c' && data[1] == 'm' && data[2] == 'p') {
    [[maybe_unused]] static volatile int sink;
    uint32_t a, b;
    memcpy(&a, data + 3, sizeof(a));
    memcpy(&b, data + 7, sizeof(b));
    sink = a < b;
  }

  // Same as above, but for memcmp.
  // If input is "mcmpABCDEFGH" (A-H - any bytes), execute a comparison
  // instruction via a 4-byte memcmp between ABCD and EFGH.
  if (size == 4 + 4 + 4 && data[0] == 'm' && data[1] == 'c' && data[2] == 'm' &&
      data[3] == 'p') {
    [[maybe_unused]] static volatile int sink;
    static volatile int kFour = 4;  // volatile to avoid memcmp inlining.
    sink = memcmp(data + 4, data + 8, kFour);
  }

  // If input is "-1", return -1.
  // LibFuzzer supports this return value as of 2022-07:
  // https://llvm.org/docs/LibFuzzer.html#rejecting-unwanted-inputs
  if (size == 2 && data[0] == '-' && data[1] == '1') {
    return -1;
  }

  // If input is pthXYZ (XYZ - any 3 bytes), call a function in
  // a function table 3 times, based on the value of X, Y, and Z.
  // depending on XYZ but not using any control flow for that.
  if (size == 6 && data[0] == 'p' && data[1] == 't' && data[2] == 'h') {
    [[maybe_unused]] static volatile int sink;
    using func_type = void (*)();
    func_type funcs[4] = {[]() { sink = 0; }, []() { sink = 1; },
                          []() { sink = 2; }, []() { sink = 3; }};
    size_t idx0 = data[3] % 4;
    size_t idx1 = data[4] % 4;
    size_t idx2 = data[5] % 4;
    funcs[idx0]();
    funcs[idx1]();
    funcs[idx2]();
  }
  IndirectCallFunc(data[0]);
  return 0;
}

// This function *may* be provided by the fuzzing engine.
extern "C" __attribute__((weak)) size_t LLVMFuzzerMutate(uint8_t *data,
                                                         size_t size,
                                                         size_t max_size);

// Test-friendly custom mutator. See
// https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md
// Reverts the bytes in `data` and sometimes adds a number in [100,107)
// at the end.
// If available, LLVMFuzzerMutate is used some of the time.
// Also returns 0 sometimes to simulate mutation failures.
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                          size_t max_size, unsigned int seed) {
  if ((seed % 3) == 0) {
    return LLVMFuzzerMutate(data, size, max_size);
  }
  // TODO(b/267096672): Remove `size > 1` once custom mutator detection is fixed
  //  in CentipedeDefaultCallbacks ctor.
  if ((seed % 3) == 1 && size > 1) {
    return 0;
  }
  for (size_t i = 0; i < size / 2; ++i) {
    std::swap(data[i], data[size - i - 1]);
  }
  if (max_size > size && (seed % 5)) {
    data[size] = 100 + (seed % 7);
    ++size;
  }
  return size;
}

// Test-friendly custom crossover. See
// https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md
// Merges the two inputs together and puts 42 between them.
extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                                            const uint8_t *data2, size_t size2,
                                            uint8_t *out, size_t max_out_size,
                                            unsigned int seed) {
  size_t new_size = size1 + size2 + 1;
  if (new_size > max_out_size) return 0;
  memcpy(out, data1, size1);
  out[size1] = 42;
  memcpy(out + size1 + 1, data2, size2);
  return new_size;
}
