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

  // Constructs an object from directly provided field values.
  WorkDir(                      //
      std::string workdir,      //
      std::string binary_name,  //
      std::string binary_hash,  //
      size_t my_shard_index);

  // Constructs an object by recording referenced to the field values in the
  // passed `env` object. NOTE: `env` must outlive this object.
  explicit WorkDir(const centipede::Environment& env);

  // Not copyable and not assignable due to dual nature of the reference
  // members (that reference either the internal value holders or an external
  // `Environment`'s members).
  WorkDir(const WorkDir &) = delete;
  WorkDir &operator=(const WorkDir &) = delete;
  WorkDir(WorkDir&&) noexcept = delete;
  WorkDir& operator=(WorkDir&&) noexcept = delete;

  // Returns the path to the coverage dir.
  std::string CoverageDirPath() const;
  // Returns the path to the crash reproducer dir.
  std::string CrashReproducerDirPath() const;
  // Returns the path where the BinaryInfo will be serialized within workdir.
  std::string BinaryInfoDirPath() const;

  // Returns the path for a corpus file by its shard_index.
  std::string CorpusPath(size_t shard_index) const;
  std::string CorpusPath() const { return CorpusPath(my_shard_index_); }
  // Returns the prefix of all corpus shards
  std::string CorpusPathPrefix() const;
  // Returns the path for the distilled corpus file for my_shard_index.
  std::string DistilledCorpusPath() const;

  // Returns the path for a features file by its shard_index.
  std::string FeaturesPath(size_t shard_index) const;
  std::string FeaturesPath() const { return FeaturesPath(my_shard_index_); }
  // Returns the prefix of all feature shards
  std::string FeaturesPathPrefix() const;
  // Returns the path for the distilled features file for my_shard_index.
  std::string DistilledFeaturesPath() const;

  // Returns the path for the coverage report file for my_shard_index.
  // Non-default `annotation` becomes a part of the returned filename.
  // `annotation` must not start with a '.'.
  std::string CoverageReportPath(std::string_view annotation = "") const;
  // Returns the path to the source-based coverage report directory.
  std::string SourceBasedCoverageReportPath(
      std::string_view annotation = "") const;
  // Returns the path to the coverage profile for this shard.
  std::string SourceBasedCoverageRawProfilePath() const;
  // Returns the path to the indexed code coverage file.
  std::string SourceBasedCoverageIndexedProfilePath() const;
  // Returns all shards' raw profile paths by scanning the coverage directory.
  std::vector<std::string> EnumerateRawCoverageProfiles() const;

  // Returns the path for the corpus stats report file for my_shard_index.
  // Non-default `annotation` becomes a part of the returned filename.
  // `annotation` must not start with a '.'.
  std::string CorpusStatsPath(std::string_view annotation = "") const;
  // Returns the path for the fuzzing progress stats report file for
  // `my_shard_index`.
  // Non-default `annotation` becomes a part of the returned filename.
  // `annotation` must not start with a '.'.
  std::string FuzzingStatsPath(std::string_view annotation = "") const;
  // Returns the path for the performance report file for my_shard_index.
  // Non-default `annotation` becomes a part of the returned filename.
  // `annotation` must not start with a '.'.
  std::string RUsageReportPath(std::string_view annotation = "") const;

 private:
  // Internal value holders for when the object is constructed from direct
  // values rather than an `Environment` object.
  std::string workdir_holder_;
  std::string binary_name_holder_;
  std::string binary_hash_holder_;
  size_t my_shard_index_holder_;

  // The references to either the internal `*_holder_` counterparts or an
  // externally passed `Environment` object's counterparts.
  const std::string &workdir_;
  const std::string &binary_name_;
  const std::string &binary_hash_;
  const size_t &my_shard_index_;
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_WORKDIR_MGR_H_
