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
#include <string>

#include "absl/base/log_severity.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/log/globals.h"
#include "absl/log/initialize.h"
#include "./centipede/seed_corpus_maker_lib.h"

ABSL_FLAG(
    std::string, config, "",
    "A silifuzz.ccmp.SeedCorpusConfig proto that describes where and how to "
    "obtain seeding corpus elements. Can be either a verbatim textproto or a "
    "path to a textproto file.\n"
    "`sources.dir_glob`s and `destination.dir_path` can be relative paths: if "
    "so, they will be resolved to absolute ones using either the --config's "
    "parent dir, if --config is a filename, or the current dir otherwise.\n"
    "Furthermore, `destination.dir_path` can be overridden by passing a "
    "non-empty --out_dir.");
ABSL_FLAG(
    std::string, out_dir, "",
    "If non-empty, overrides the `destination.dir_path` field in the resolved "
    "--config protobuf.");

int main(int argc, char** argv) {
  // NB: The invocation order below is important.
  // By default, log everything to stderr. Overridable by --stderrthreshold=N.
  absl::SetStderrThreshold(absl::LogSeverityAtLeast::kInfo);
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  const std::string config_spec = absl::GetFlag(FLAGS_config);
  QCHECK(!config_spec.empty());
  const std::string out_dir = absl::GetFlag(FLAGS_out_dir);

  centipede::GenerateSeedCorpusFromConfig(config_spec, out_dir);

  return EXIT_SUCCESS;
}
