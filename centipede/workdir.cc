// Copyright 2022 The Centipede Authors.
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

#include "./centipede/workdir.h"

#include <cstddef>
#include <filesystem>  // NOLINT
#include <string>
#include <string_view>
#include <system_error>  // NOLINT
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "./centipede/environment.h"

namespace centipede {

namespace {

// If `annotation` is empty, returns an empty string. Otherwise, verifies that
// it does not start with a dot and returns it with a dot prepended.
std::string NormalizeAnnotation(std::string_view annotation) {
  std::string ret;
  if (!annotation.empty()) {
    CHECK_NE(annotation.front(), '.');
    ret = absl::StrCat(".", annotation);
  }
  return ret;
}

}  // namespace

WorkDir::WorkDir(const centipede::Environment& env) : env_(env) {}

std::string WorkDir::CoverageDirPath() const {
  return std::filesystem::path(env_.workdir) /
         absl::StrCat(env_.binary_name, "-", env_.binary_hash);
}

std::string WorkDir::CrashReproducerDirPath() const {
  return std::filesystem::path(env_.workdir) / "crashes";
}

std::string WorkDir::CorpusPath(size_t shard_index) const {
  return std::filesystem::path(env_.workdir) /
         absl::StrFormat("corpus.%0*d", kDigitsInShardIndex, shard_index);
}

std::string WorkDir::FeaturesPath(size_t shard_index) const {
  return std::filesystem::path(CoverageDirPath()) /
         absl::StrFormat("features.%0*d", kDigitsInShardIndex, shard_index);
}

std::string WorkDir::DistilledCorpusPath() const {
  return std::filesystem::path(env_.workdir) /
         absl::StrFormat("distilled-%s.%0*d", env_.binary_name,
                         kDigitsInShardIndex, env_.my_shard_index);
}

std::string WorkDir::DistilledFeaturesPath() const {
  return std::filesystem::path(CoverageDirPath()).append(
      absl::StrFormat("distilled-features-%s.%0*d", env_.binary_name,
                      kDigitsInShardIndex, env_.my_shard_index));
}

std::string WorkDir::CoverageReportPath(std::string_view annotation) const {
  return std::filesystem::path(env_.workdir) /
         absl::StrFormat("coverage-report-%s.%0*d%s.txt", env_.binary_name,
                         kDigitsInShardIndex, env_.my_shard_index,
                         NormalizeAnnotation(annotation));
}

std::string WorkDir::CorpusStatsPath(std::string_view annotation) const {
  return std::filesystem::path(env_.workdir) /
         absl::StrFormat("corpus-stats-%s.%0*d%s.json", env_.binary_name,
                         kDigitsInShardIndex, env_.my_shard_index,
                         NormalizeAnnotation(annotation));
}

std::string WorkDir::FuzzingStatsPath(std::string_view annotation) const {
  return std::filesystem::path(env_.workdir) /
         absl::StrFormat("fuzzing-stats-%s.%0*d%s.csv", env_.binary_name,
                         kDigitsInShardIndex, env_.my_shard_index,
                         NormalizeAnnotation(annotation));
}

std::string WorkDir::SourceBasedCoverageRawProfilePath() const {
  // Pass %m to enable online merge mode: updates file in place instead of
  // replacing it %m is replaced by lprofGetLoadModuleSignature(void) which
  // should be consistent for a fixed binary
  return std::filesystem::path(CoverageDirPath()) /
         absl::StrFormat("clang_coverage.%0*d.%s.profraw", kDigitsInShardIndex,
                         env_.my_shard_index, "%m");
}

std::string WorkDir::SourceBasedCoverageIndexedProfilePath() const {
  return std::filesystem::path(CoverageDirPath()) /
         absl::StrFormat("clang_coverage.profdata");
}

std::string WorkDir::SourceBasedCoverageReportPath(
    std::string_view annotation) const {
  return std::filesystem::path(env_.workdir) /
         absl::StrFormat("source-coverage-report-%s.%0*d%s", env_.binary_name,
                         kDigitsInShardIndex, env_.my_shard_index,
                         NormalizeAnnotation(annotation));
}

std::string WorkDir::RUsageReportPath(std::string_view annotation) const {
  return std::filesystem::path(env_.workdir) / (absl::StrFormat(
      "rusage-report-%s.%0*d%s.txt", env_.binary_name, kDigitsInShardIndex,
      env_.my_shard_index, NormalizeAnnotation(annotation)));
}

std::vector<std::string> WorkDir::EnumerateRawCoverageProfiles() const {
  // Unfortunately we have to enumerate the profiles from the filesystem since
  // clang-coverage generates its own hash of the binary to avoid collisions
  // between builds. We account for this in Centipede already with the
  // per-binary coverage directory but LLVM coverage (perhaps smartly) doesn't
  // trust the user to get this right. We could call __llvm_profile_get_filename
  // in the runner and plumb it back to us but this is simpler.
  const std::string dir_path = CoverageDirPath();
  std::error_code dir_error;
  const auto dir_iter =
      std::filesystem::directory_iterator(dir_path, dir_error);
  if (dir_error) {
    LOG(ERROR) << "Failed to access coverage dir '" << dir_path
               << "': " << dir_error.message();
    return {};
  }
  std::vector<std::string> raw_profiles;
  for (const auto &entry : dir_iter) {
    if (entry.is_regular_file() && entry.path().extension() == ".profraw")
      raw_profiles.push_back(entry.path());
  }
  return raw_profiles;
}

}  // namespace centipede

