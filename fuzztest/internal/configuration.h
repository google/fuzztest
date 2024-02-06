#ifndef FUZZTEST_FUZZTEST_INTERNAL_CONFIGURATION_H_
#define FUZZTEST_FUZZTEST_INTERNAL_CONFIGURATION_H_

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "absl/time/time.h"

namespace fuzztest::internal {

class CorpusDatabase {
 public:
  explicit CorpusDatabase(absl::string_view database_path,
                          bool use_coverage_inputs, bool use_crashing_inputs)
      : database_path_(std::string(database_path)),
        use_coverage_inputs_(use_coverage_inputs),
        use_crashing_inputs_(use_crashing_inputs) {}

  // Returns set of all regression inputs from `corpus_database` for a fuzz
  // test.
  std::vector<std::string> GetRegressionInputs(
      absl::string_view test_name) const;

  // Returns set of all corpus inputs from `corpus_database` for a fuzz test.
  // Returns an empty set when `use_coverage_inputs_` is false.
  std::vector<std::string> GetCoverageInputsIfAny(
      absl::string_view test_name) const;

  // Returns set of all crashing inputs from `corpus_database` for a fuzz test.
  // Returns an empty set when `use_crashing_inputs_` is false.
  std::vector<std::string> GetCrashingInputsIfAny(
      absl::string_view test_name) const;

 private:
  std::string database_path_;
  bool use_coverage_inputs_ = false;
  bool use_crashing_inputs_ = false;
};

// All the configurations consumed by a fuzz test
struct Configuration {
  CorpusDatabase corpus_database;

  // Stack limit in bytes.
  size_t stack_limit;
  // RSS limit in bytes.
  size_t rss_limit;
  // Time limit per test input.
  absl::Duration time_limit_per_input;

  // When set, `FuzzTestFuzzer` replays only one input (no fuzzing is done).
  std::optional<std::string> crashing_input_to_reproduce;

  // Preprocessing step for reproducing crashing input
  std::function<void()> preprocess_crash_reproducing = [] {};
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_CONFIGURATION_H_
