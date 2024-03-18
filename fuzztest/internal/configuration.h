// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef FUZZTEST_FUZZTEST_INTERNAL_CONFIGURATION_H_
#define FUZZTEST_FUZZTEST_INTERNAL_CONFIGURATION_H_

#include <cstddef>
#include <functional>
#include <optional>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"

namespace fuzztest::internal {

// The configuration of a fuzz test.
struct Configuration {
  // The location of the database that contains coverage, regression, and
  // crashing inputs for each test binary and fuzz test in the project (eg.,
  // ~/.cache/fuzztest).
  std::string corpus_database;
  // The identifier of the test binary in the corpus database (eg.,
  // relative/path/to/binary).
  std::string binary_identifier;
  // Generate separate TESTs that replay crashing inputs for the selected fuzz
  // tests.
  bool reproduce_findings_as_separate_tests = false;
  // Replay coverage inputs for the selected fuzz tests.
  bool replay_coverage_inputs = false;

  // Stack limit in bytes.
  size_t stack_limit = 128 * 1024;
  // RSS limit in bytes. Zero indicates no limit.
  size_t rss_limit = 0;
  // Time limit per test input.
  absl::Duration time_limit_per_input = absl::InfiniteDuration();

  // When set, `FuzzTestFuzzer` replays only one input (no fuzzing is done).
  std::optional<std::string> crashing_input_to_reproduce;

  // Preprocessing step for reproducing crashing input.
  // Note: This field is not serialized and deserialized.
  // TODO(b/329709054): Consider eliminating the field.
  std::function<void()> preprocess_crash_reproducing = [] {};

  std::string Serialize() const;
  static absl::StatusOr<Configuration> Deserialize(
      absl::string_view serialized);
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_CONFIGURATION_H_
