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

#ifndef THIRD_PARTY_CENTIPEDE_RUNNER_UTILS_H_
#define THIRD_PARTY_CENTIPEDE_RUNNER_UTILS_H_

#include <sys/stat.h>

#include <cstdint>
#include <cstdio>
#include <vector>

#include "absl/base/nullability.h"

namespace fuzztest::internal {

// If `condition` prints `error` and calls exit(1).
// TODO(kcc): change all uses of PrintErrorAndExitIf() to RunnerCheck()
// as it is a more common pattern.
void PrintErrorAndExitIf(bool condition, const char* absl_nonnull error);

// A rough equivalent of "CHECK(condition) << error;".
inline void RunnerCheck(bool condition, const char* absl_nonnull error) {
  PrintErrorAndExitIf(!condition, error);
}

// Returns the lower bound of the stack region for the current thread. 0 will be
// returned on failures.
uintptr_t GetCurrentThreadStackRegionLow();

template <typename Type>
std::vector<Type> ReadBytesFromFilePath(const char* input_path) {
  FILE* input_file = fopen(input_path, "rb");
  RunnerCheck(input_file != nullptr, "can't open the input file");
  struct stat statbuf = {};
  RunnerCheck(fstat(fileno(input_file), &statbuf) == 0, "fstat failed");
  size_t size_in_bytes = statbuf.st_size;
  RunnerCheck(size_in_bytes != 0, "empty file");
  RunnerCheck((size_in_bytes % sizeof(Type)) == 0,
              "file size is not multiple of the type size");
  std::vector<Type> data(size_in_bytes / sizeof(Type));
  auto num_bytes_read = fread(data.data(), 1, size_in_bytes, input_file);
  RunnerCheck(num_bytes_read == size_in_bytes, "read failed");
  RunnerCheck(fclose(input_file) == 0, "fclose failed");
  return data;
}

// Reads `size` bytes to `data` from `fd` with retires (assuming `fd` is
// blocking so there is no busy-spinning). Returns true if all bytes are
// written, false otherwise due to errors.
bool ReadAll(int fd, char* data, size_t size);

// Writes `size` bytes from `data` to `fd` with retires (assuming `fd` is
// blocking so there is no busy-spinning). Returns true if all bytes are
// written, false otherwise due to errors.
bool WriteAll(int fd, const char* data, size_t size);

}  // namespace fuzztest::internal

#endif  // THIRD_PARTY_CENTIPEDE_RUNNER_UTILS_H_
