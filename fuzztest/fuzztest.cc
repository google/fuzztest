// Copyright 2022 Google LLC
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

#include "./fuzztest/fuzztest.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <tuple>

#include "absl/strings/match.h"
#include "absl/strings/str_format.h"
#include "./fuzztest/internal/registry.h"

namespace fuzztest {

std::vector<std::string> ListRegisteredTests() {
  std::vector<std::string> result;
  internal::ForEachTest(
      [&](const auto& test) { result.push_back(test.full_name()); });
  return result;
}

std::string GetMatchingFuzzTestOrExit(std::string_view name) {
  const std::string partial_name(name);
  const std::vector<std::string> full_names = ListRegisteredTests();
  std::vector<const std::string*> matches;
  for (const std::string& full_name : full_names) {
    if (absl::StrContains(full_name, partial_name)) {
      if (full_name == partial_name) {
        // In case of an exact match, we end the search and use it. This is to
        // handle the case when we want to select `MySuite.MyTest`, but the
        // binary has both `MySuite.MyTest` and `MySuite.MyTestX`.
        return full_name;
      } else {
        matches.push_back(&full_name);
      }
    }
  }

  if (matches.empty()) {
    absl::FPrintF(stderr, "\n\nNo FUZZ_TEST matches the name: %s\n\n", name);
    absl::FPrintF(stderr, "Valid tests:\n");
    for (const std::string& full_name : full_names) {
      absl::FPrintF(stderr, " %s\n", full_name);
    }
    exit(1);
  } else if (matches.size() > 1) {
    absl::FPrintF(stderr, "\n\nMultiple FUZZ_TESTs match the name: %s\n\n",
                  name);
    absl::FPrintF(stderr, "Please select one. Matching tests:\n");
    for (const std::string* full_name : matches) {
      absl::FPrintF(stderr, " %s\n", *full_name);
    }
    exit(1);
  }
  return *matches[0];
}

void RunSpecifiedFuzzTest(std::string_view name) {
  const std::string matching_fuzz_test = GetMatchingFuzzTestOrExit(name);
  internal::ForEachTest([&](const auto& test) {
    if (test.full_name() == matching_fuzz_test) {
      exit(test.make()->RunInFuzzingMode(/*argc=*/nullptr, /*argv=*/nullptr));
    }
  });
}

std::vector<std::tuple<std::string>> ReadFilesFromDirectory(
    std::string_view dir) {
  std::vector<internal::FilePathAndData> files =
      internal::ReadFileOrDirectory(dir);

  std::vector<std::tuple<std::string>> out;
  out.reserve(files.size());

  for (const internal::FilePathAndData& file : files) {
    out.push_back(std::make_tuple(file.data));
  }

  return out;
}

}  // namespace fuzztest
