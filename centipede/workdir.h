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
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include "./centipede/defs.h"
#include "./centipede/environment.h"

namespace centipede {

// The Centipede work directory manager.
class WorkDir {
 public:
  // Min number of decimal digits in a shard index given `total_shards`. Used to
  // pad indices with 0's in output file names so the names are sorted by index.
  static constexpr int kDigitsInShardIndex = 6;

  // Provides APIs for getting paths of a particular category of sharded files.
  class ShardedFileInfo {
   public:
    // Returns the path of the shard file for `shard_index`.
    std::string ShardPath(size_t shard_index) const;
    // Returns the path of the shard file for `my_shard_index_`.
    std::string MyShardPath() const;
    // Returns a glob matching all the shard files.
    std::string AllShardsGlob() const;
    // Returns true if `path` looks like a shard file path from this set.
    // Matching is purely lexicographical: the actual file doesn't have to exist
    // on disk, but `path` must have the exact `base_dir`/`rel_prefix` prefix,
    // including any relative "." and ".." path elements.
    bool IsShardPath(std::string_view path) const;

   private:
    friend class WorkDir;

    ShardedFileInfo(std::string_view base_dir, std::string_view rel_prefix,
                    size_t my_shard_index);

    const std::string prefix_;
    const size_t my_shard_index_;
  };

  // Deduces the workdir properties from a provided corpus shard path and
  // coverage binary basename and hash.
  static WorkDir FromCorpusShardPath(      //
      std::string_view corpus_shard_path,  //
      std::string_view binary_name,        //
      std::string_view binary_hash);

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

  // Comparisons and debugging I/O (mainly for tests).
  friend bool operator==(const WorkDir &a, const WorkDir &b) {
    return a.workdir_ == b.workdir_ && a.binary_name_ == b.binary_name_ &&
           a.binary_hash_ == b.binary_hash_ &&
           a.my_shard_index_ == b.my_shard_index_;
  }
  friend bool operator!=(const WorkDir &a, const WorkDir &b) {
    return !(a == b);
  }
  friend std::ostream &operator<<(std::ostream &os, const WorkDir &wd) {
    return os << VV(wd.workdir_) << VV(wd.binary_name_) << VV(wd.binary_hash_)
              << VV(wd.my_shard_index_);
  }

  // Returns the path to the coverage dir.
  std::string CoverageDirPath() const;
  // Returns the path to the crash reproducer dir.
  std::string CrashReproducerDirPath() const;
  // Returns the path where the BinaryInfo will be serialized within workdir.
  std::string BinaryInfoDirPath() const;

  // Returns the path info for the corpus files.
  ShardedFileInfo CorpusFiles() const;
  // Returns the path info for the distilled corpus files.
  ShardedFileInfo DistilledCorpusFiles() const;
  // Returns the path info for the features files.
  ShardedFileInfo FeaturesFiles() const;
  // Returns the path info for the distilled features files.
  ShardedFileInfo DistilledFeaturesFiles() const;

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
