#include "./fuzztest/internal/configuration.h"

#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/internal/io.h"

namespace fuzztest::internal {

std::vector<std::string> CorpusDatabase::GetCrashingInputs(
    absl::string_view test_name) const {
  if (!replay_crashing_) return {};
  return ListDirectory(
      absl::StrCat(database_path_, "/", test_name, "/crashing"));
}

std::vector<std::string> CorpusDatabase::GetNonCrashingInputs(
    absl::string_view test_name) const {
  std::vector<std::string> result = internal::ListDirectory(
      absl::StrCat(database_path_, "/", test_name, "/regression"));
  if (non_crashing_inputs_ == CorpusDatabase::NonCrashingInputs::kRegression) {
    return result;
  }
  std::vector<std::string> coverage = internal::ListDirectory(
      absl::StrCat(database_path_, "/", test_name, "/coverage"));
  result.insert(result.end(), coverage.begin(), coverage.end());
  return result;
}

}  // namespace fuzztest::internal
