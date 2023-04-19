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

// A simple standalone binary that takes one file path as an argument.
// It reads that file and traps if the file starts with 'fuz'.
// Returns EXIT_FAILURE on any error.
//
// For testing how Centipede can fuzz standalone binaries with their main().
#include <cstdint>
#include <cstdio>
#include <cstdlib>

// Separate no-inline function so that the compiler doesn't know
// the size of `data`. Crashes when the input starts with 'fuz'.
__attribute__((noinline)) static void FuzzMe(const uint8_t* data, size_t size) {
  if (size >= 3 && data[0] == 'f' && data[1] == 'u' && data[2] == 'z')
    __builtin_trap();
}

int main(int argc, char* argv[]) {
  if (argc != 2) return EXIT_FAILURE;
  constexpr size_t kMaxSize = 1000;
  uint8_t bytes[kMaxSize] = {};
  FILE* f = fopen(argv[1], "r");
  if (!f) return EXIT_FAILURE;
  auto n_bytes = fread(bytes, 1, kMaxSize, f);
  if (n_bytes == 0) return EXIT_FAILURE;
  if (fclose(f) != 0) return EXIT_FAILURE;
  FuzzMe(bytes, n_bytes);
}
