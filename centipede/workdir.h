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

#ifndef THIRD_PARTY_CENTIPEDE_WORKDIR_MGR_H_
#define THIRD_PARTY_CENTIPEDE_WORKDIR_MGR_H_

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "./centipede/environment.h"

namespace centipede {

// The Centipede work directory manager.
class WorkDir {
 public:
  // Min number of decimal digits in a shard index given `total_shards`. Used to
  // pad indices with 0's in output file names so the names are sorted by index.
  static constexpr int kDigitsInShardIndex = 6;

  // NOTE: `env` is stored by-reference and must outlive this object.
  explicit WorkDir(const centipede::Environment& env);

  // Copy- and move-constructible only (due to const members).
  WorkDir(const WorkDir&) = default;
  WorkDir& operator=(const WorkDir&) = default;
  WorkDir(WorkDir&&) noexcept = delete;
  WorkDir& operator=(WorkDir&&) noexcept = delete;

  // Returns the path to the coverage dir.
  std::string CoverageDirPath() const;
  // Returns the path to the crash reproducer dir.
  std::string CrashReproducerDirPath() const;
  // Returns the path for a corpus file by its shard_index.
  std::string CorpusPath(size_t shard_index) const;
  // Returns the path for a features file by its shard_index.
  std::string FeaturesPath(size_t shard_index) const;
  // Returns the path to the coverage profile for this shard.
  std::string SourceBasedCoverageRawProfilePath() const;
  // Returns the path to the indexed code coverage file.
  std::string SourceBasedCoverageIndexedProfilePath() const;
  // Returns the path for the distilled corpus file for my_shard_index.
  std::string DistilledCorpusPath() const;
  // Returns the path for the distilled features file for my_shard_index.
  std::string DistilledFeaturesPath() const;
  // Returns the path for the coverage report file for my_shard_index.
  // Non-default `annotation` becomes a part of the returned filename.
  // `annotation` must not start with a '.'.
  std::string CoverageReportPath(std::string_view annotation = "") const;
  // Returns the path for the corpus stats report file for my_shard_index.
  // Non-default `annotation` becomes a part of the returned filename.
  // `annotation` must not start with a '.'.
  std::string CorpusStatsPath(std::string_view annotation = "") const;
  // Returns the path for the fuzzing progress stats report file for
  // `my_shard_index`.
  // Non-default `annotation` becomes a part of the returned filename.
  // `annotation` must not start with a '.'.
  std::string FuzzingStatsPath(std::string_view annotation = "") const;
  // Returns the path to the source-based coverage report directory.
  std::string SourceBasedCoverageReportPath(
      std::string_view annotation = "") const;
  // Returns the path for the performance report file for my_shard_index.
  // Non-default `annotation` becomes a part of the returned filename.
  // `annotation` must not start with a '.'.
  std::string RUsageReportPath(std::string_view annotation = "") const;
  // Returns all shards' raw profile paths by scanning the coverage directory.
  std::vector<std::string> EnumerateRawCoverageProfiles() const;

 private:
  // TODO(b/295978603): We really just need a few vars from `Environment`, so we
  //  could store just those. However, a thorough check is necessary before
  //  doing that, because we sometimes modify `Environment` objects after
  //  creation.
  const Environment& env_;
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_WORKDIR_MGR_H_
