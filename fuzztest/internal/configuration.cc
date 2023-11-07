#include "./fuzztest/internal/configuration.h"

#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/internal/io.h"

namespace fuzztest::internal {

namespace {
std::vector<std::string> GetInputs(absl::string_view database_path,
                                   absl::string_view test_name,
                                   absl::string_view subdir) {
  return ListDirectory(
      absl::StrCat(database_path, "/", test_name, "/", subdir));
}
}  // namespace

std::vector<std::string> CorpusDatabase::GetRegressionInputs(
    absl::string_view test_name) const {
  return GetInputs(database_path_, test_name, "regression");
}

std::vector<std::string> CorpusDatabase::GetCrashingInputsIfAny(
    absl::string_view test_name) const {
  if (!use_crashing_inputs_) return {};
  return GetInputs(database_path_, test_name, "crashing");
}

std::vector<std::string> CorpusDatabase::GetCoverageInputsIfAny(
    absl::string_view test_name) const {
  if (!use_coverage_inputs_) return {};
  return GetInputs(database_path_, test_name, "coverage");
}

}  // namespace fuzztest::internal
