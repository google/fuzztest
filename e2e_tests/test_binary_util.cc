// Copyright 2024 Google LLC
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

#include "./e2e_tests/test_binary_util.h"

#include <cstdlib>
#include <filesystem>  // NOLINT
#include <string>
#include <system_error>  // NOLINT
#include <vector>

#include "absl/log/check.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/internal/flag_name.h"
#include "./fuzztest/internal/subprocess.h"

namespace fuzztest::internal {
namespace {

// Returns the full path for `relative_path` given relative to the FuzzTest
// root.
std::string GetFullPath(const std::filesystem::path& relative_path) {
  const auto test_srcdir = absl::NullSafeStringView(std::getenv("TEST_SRCDIR"));
  CHECK(!test_srcdir.empty()) << "Please set TEST_SRCDIR to non-empty value or "
                                 "use bazel to run the test.";
  const std::string full_path =
      std::filesystem::path(test_srcdir) / "_main"
      / relative_path;
  CHECK(std::filesystem::exists(full_path)) << "Can't find " << full_path;
  return full_path;
}

}  // namespace

std::string CreateFuzzTestFlag(absl::string_view flag_name,
                               absl::string_view flag_value) {
  return absl::StrCat("--", FUZZTEST_FLAG_PREFIX, flag_name,
                      (flag_value.empty() ? "" : "="), flag_value);
}

std::string BinaryPath(const absl::string_view relative_path) {
  return GetFullPath(
      std::filesystem::path("e2e_tests") /
      absl::StrCat(relative_path, absl::EndsWith(relative_path, ".stripped")
                                      ? ""
                                      : ".stripped"));
}

std::string CentipedePath() {
  return GetFullPath(std::filesystem::path("centipede") /
                     "centipede_uninstrumented");
}

RunResults RunBinary(absl::string_view binary_path, const RunOptions& options) {
  std::vector<std::string> args;
  args.reserve(1 + options.fuzztest_flags.size() + options.flags.size() +
               options.raw_args.size());
  args.push_back(std::string(binary_path));
  for (const auto& [key, value] : options.fuzztest_flags) {
    args.push_back(CreateFuzzTestFlag(key, value));
  }
  for (const auto& [key, value] : options.flags) {
    args.push_back(absl::StrCat("--", key, "=", value));
  }
  args.insert(args.end(), options.raw_args.begin(), options.raw_args.end());
  return RunCommand(args, options.env, options.timeout);
}

}  // namespace fuzztest::internal
