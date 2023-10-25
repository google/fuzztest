#ifndef FUZZTEST_FUZZTEST_INTERNAL_CONFIGURATION_H_
#define FUZZTEST_FUZZTEST_INTERNAL_CONFIGURATION_H_

#include <optional>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"

namespace fuzztest::internal {

class CorpusDatabase {
 public:
  enum class NonCrashingInputs {
    kRegression,  // Regression inputs
    kAll          // Regression inputs and minimized corpus
  };

  explicit CorpusDatabase(absl::string_view database_path,
                          NonCrashingInputs non_crashing_inputs,
                          bool replay_crashing)
      : database_path_(std::string(database_path)),
        non_crashing_inputs_(non_crashing_inputs),
        replay_crashing_(replay_crashing) {}

  // TODO(b/301965259): Return set of "regression inputs" when not replaying.

  // Returns set of all non-crashing inputs from `database_path` for a FuzzTest
  // when `replay_non_crashing` is true. Otherwise, returns an empty set.
  std::vector<std::string> GetNonCrashingInputs(
      absl::string_view test_name) const;

  // Returns set of all crashing inputs from `corpus_database` for a FuzzTest.
  std::vector<std::string> GetCrashingInputs(absl::string_view test_name) const;

 private:
  std::string database_path_;
  // The subset of non-crashing inputs in corpus to replay.
  NonCrashingInputs non_crashing_inputs_ = NonCrashingInputs::kRegression;
  // Should replay crashing inputs in corpus.
  bool replay_crashing_ = false;
};

// All the configurations consumed by a FuzzTest
struct Configuration {
  // The default corpus.
  CorpusDatabase corpus_database;

  // When set, `FuzzTestFuzzer` replays only one input (no fuzzing is done).
  std::optional<std::string> crashing_input_to_reproduce;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_CONFIGURATION_H_
