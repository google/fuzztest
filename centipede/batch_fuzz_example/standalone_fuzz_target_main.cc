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
#include <cstring>
#include <filesystem>  // NOLINT
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./centipede/runner_interface.h"

static void FuzzMe(const char* data, size_t size) {
  if (size >= 3 && data[0] == 'f' && data[1] == 'u' && data[2] == 'z') {
    std::cout << "Catch you: " << data << std::endl;
    __builtin_trap();
  }
  if (size == 3 && data[0] == 's' && data[1] == 'l' && data[2] == 'p') {
    absl::SleepFor(absl::Seconds(10));
  }
  if (size == 3 && data[0] == 'o' && data[1] == 'o' && data[2] == 'm') {
    [[maybe_unused]] static volatile void* ptr_sink = nullptr;
    const size_t oom_allocation_size = 1ULL << 32;
    void* ptr = malloc(oom_allocation_size);
    memset(ptr, 42, oom_allocation_size);
    ptr_sink = ptr;
    free(ptr);
  }
}

// This binary takes three input flags:
// - input_file: Path to a file containing a list of file names, one per line.
// - output_dir: Path to the directory where the binary will write the execution
//   results for the analyzed files.
// - enable_feature_only_feedback: Optional flag. If specified, the binary will
//   output coverage features after processing each input file. Otherwise, it
//   will only output the execution result.
int main(int argc, char* argv[]) {
  std::string input_file_path;
  std::string output_dir;
  bool feature_only_feedback = false;
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--input_file") == 0) {
      if (i + 1 < argc) input_file_path = argv[i + 1];
    } else if (strcmp(argv[i], "--output_dir") == 0) {
      if (i + 1 < argc) output_dir = argv[i + 1];
    } else if (strcmp(argv[i], "--enable_feature_only_feedback") == 0) {
      feature_only_feedback = true;
    }
  }

  std::ifstream input_file(input_file_path);
  if (!input_file.is_open()) {
    std::cerr << "Failed to open --input_file: " << input_file_path
              << std::endl;
    return EXIT_FAILURE;
  }

  if (!std::filesystem::exists(output_dir)) {
    std::cerr << "Not found --output_dir: " << output_dir << std::endl;
    return EXIT_FAILURE;
  }

  static constexpr size_t kOutputLimit = 5000;
  std::string curr_filepath;

  size_t index = 0;
  while (getline(input_file, curr_filepath)) {
    std::string input_data;
    std::ifstream curr_file(curr_filepath);
    if (!curr_file.is_open()) {
      std::cerr << "Failed to open input file: " << curr_filepath << std::endl;
      return EXIT_FAILURE;
    }

    input_data.assign(std::istreambuf_iterator<char>(curr_file),
                      std::istreambuf_iterator<char>());
    std::string output;
    output.resize(kOutputLimit);

    CentipedePrepareProcessing();

    FuzzMe(input_data.data(), input_data.size());

    CentipedeFinalizeProcessing();

    size_t output_data_size = 0;
    if (feature_only_feedback) {
      output_data_size = CentipedeGetCoverageData(
          reinterpret_cast<uint8_t*>(output.data()), output.size());
    } else {
      output_data_size = CentipedeGetExecutionResult(
          reinterpret_cast<uint8_t*>(output.data()), output.size());
    }

    if (output_data_size == 0) {
      std::cerr << "Failed to get coverage data";
      return EXIT_FAILURE;
    }

    const std::string output_filename =
        std::filesystem::path(output_dir)
            .append("output." + std::to_string(++index));
    std::ofstream output_file(output_filename, std::ios::out);
    if (!output_file.is_open()) {
      std::cerr << "Failed to open file: " << output_filename << std::endl;
      return EXIT_FAILURE;
    }

    output_file.write(output.data(), output_data_size);
    curr_file.close();
  }
  return EXIT_SUCCESS;
}
