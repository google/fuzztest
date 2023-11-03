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

#include <cstdlib>
#include <filesystem>  // NOLINT
#include <string>

#include "absl/flags/flag.h"
#include "./centipede/config_init.h"
#include "./centipede/seed_corpus_maker_flags.h"
#include "./centipede/seed_corpus_maker_lib.h"
#include "./centipede/util.h"

int main(int argc, char** argv) {
  (void)centipede::config::InitRuntime(argc, argv);

  const std::string config = absl::GetFlag(FLAGS_config);
  const std::string binary_path = absl::GetFlag(FLAGS_coverage_binary_path);
  std::string binary_hash = absl::GetFlag(FLAGS_coverage_binary_hash);
  if (binary_hash.empty() && !binary_path.empty()) {
    binary_hash = centipede::HashOfFileContents(binary_path);
  }
  const std::string binary_name = std::filesystem::path{binary_path}.filename();
  const std::string override_out_dir = absl::GetFlag(FLAGS_override_out_dir);

  centipede::GenerateSeedCorpusFromConfig(  //
      config, binary_name, binary_hash, override_out_dir);

  return EXIT_SUCCESS;
}
