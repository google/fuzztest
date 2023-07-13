// Copyright 2023 The Centipede Authors.
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
//
// For testing how Centipede can consume the periodically collected coverage in
// a standalone binary.

#include <sys/types.h>

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

#include "./centipede/runner_interface.h"

static void FuzzMe(const char* data, size_t size) {
  if (size >= 3 && data[0] == 'f' && data[1] == 'u' && data[2] == 'z') {
    std::cout << "Catch you: " << data << std::endl;
    __builtin_trap();
  }
}

// - argv[1]: the path to the input file. This file should contain a list of
// file names, one per line.
// - argv[2]: the path to the output file. This file will contain the execution
// results of exercising the files listed in the input file.
int main(int argc, char* argv[]) {
  if (argc != 3) return EXIT_FAILURE;

  std::ifstream input_file(argv[1]);
  if (!input_file.is_open()) {
    std::cerr << "Failed to open file arg[1]: " << argv[1] << std::endl;
    return EXIT_FAILURE;
  }
  std::ofstream output_file(argv[2], std::ios::out);
  if (!output_file.is_open()) {
    std::cerr << "Failed to open file arg[2]: " << argv[2] << std::endl;
    return EXIT_FAILURE;
  }
  static constexpr int kMaxOutputLimit = 1000;
  std::string curr_filepath;

  while (getline(input_file, curr_filepath)) {
    std::string input_data;
    std::ifstream curr_file(curr_filepath);
    if (curr_file.is_open()) {
      input_data.assign(std::istreambuf_iterator<char>(curr_file),
                        std::istreambuf_iterator<char>());
    } else {
      std::cerr << "Failed to open input file: " << curr_filepath << std::endl;
      return EXIT_FAILURE;
    }
    std::string output;
    output.resize(kMaxOutputLimit);

    CentipedeClearExecutionResult();

    FuzzMe(input_data.data(), input_data.size());
    const size_t offset = CentipedeGetExecutionResult(
        reinterpret_cast<uint8_t*>(output.data()), kMaxOutputLimit);
    if (offset == 0) {
      std::cerr << "Failed to dump output execution results.";
      return EXIT_FAILURE;
    }
    output_file.write(output.data(), offset);
    curr_file.close();
  }
  return EXIT_SUCCESS;
}
