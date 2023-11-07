#ifndef FUZZTEST_FUZZTEST_INTERNAL_CONFIGURATION_H_
#define FUZZTEST_FUZZTEST_INTERNAL_CONFIGURATION_H_

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"

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
  explicit Configuration(
      CorpusDatabase corpus_database,
      std::optional<std::string> crashing_input_to_reproduce = std::nullopt)
      : corpus_database(std::move(corpus_database)),
        crashing_input_to_reproduce(std::move(crashing_input_to_reproduce)) {}

  CorpusDatabase corpus_database;

  // When set, `FuzzTestFuzzer` replays only one input (no fuzzing is done).
  std::optional<std::string> crashing_input_to_reproduce;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_CONFIGURATION_H_
