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

#ifndef THIRD_PARTY_CENTIPEDE_INTERNAL_TEST_UTIL_H_
#define THIRD_PARTY_CENTIPEDE_INTERNAL_TEST_UTIL_H_

#include <filesystem>
#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "./centipede/defs.h"
#include "./centipede/util.h"

#include "./centipede/logging.h"

#define EXPECT_OK(status) EXPECT_TRUE((status).ok()) << VV(status)
#define ASSERT_OK(status) ASSERT_TRUE((status).ok()) << VV(status)

namespace centipede {

// Returns a temp dir for use inside tests. The base dir is chosen in the
// following order of precedence:
// - $TEST_TMPDIR (highest)
// - $TMPDIR
// - /tmp
//
// An optional `subdir` can be appended to the base dir chosen as above. One
// useful value always available inside a TEST macro (and its variations) is
// `test_into_->name()`, which returns the name of the test case.
//
// If the final dir doesn't exist, it gets created.
std::string GetTestTempDir(std::string_view subdir = "");

// Returns the root directory filepath for a test's "runfiles".
std::filesystem::path GetTestRunfilesDir();

// Returns the filepath of a test's data dependency file.
std::filesystem::path GetDataDependencyFilepath(std::string_view rel_path);

// Resets the PATH envvar to "`dir`:$PATH".
void PrependDirToPathEnvvar(std::string_view dir);

// Creates or clears a tmp dir in CTOR. The dir will end with `leaf` subdir.
class TempDir {
 public:
  explicit TempDir(std::string_view leaf1, std::string_view leaf2 = "")
      : path_{std::filesystem::path(GetTestTempDir()) / leaf1 / leaf2} {
    std::filesystem::remove_all(path_);
    std::filesystem::create_directories(path_);
  }

  const std::filesystem::path& path() const { return path_; }

  std::string GetFilePath(std::string_view file_name) const {
    return path_ / file_name;
  }

  std::string CreateSubdir(std::string_view name) const {
    std::string path = GetFilePath(name);
    std::filesystem::remove_all(path);
    std::filesystem::create_directories(path);
    return path;
  }

 private:
  std::filesystem::path path_;
};

class TempCorpusDir : public TempDir {
 public:
  // Reuse the parent's ctor.
  using TempDir::TempDir;

  // Loads the corpus from the file `name_prefix``shard_index`
  // and returns it as a vector<ByteArray>.
  std::vector<ByteArray> GetCorpus(size_t shard_index,
                                   std::string_view name_prefix = "corpus.") {
    ByteArray corpus_data;
    // NOTE: The "6" in the "%06d" comes from kDigitsInShardIndex in
    // environment.cc.
    ReadFromLocalFile(
        GetFilePath(absl::StrFormat("%s%06d", name_prefix, shard_index)),
        corpus_data);
    std::vector<ByteArray> corpus;
    UnpackBytesFromAppendFile(corpus_data, &corpus);
    return corpus;
  }

  // Returns the count of elements in the corpus file `path`/`file_name`.
  size_t CountElementsInCorpusFile(size_t shard_index,
                                   std::string_view name_prefix = "corpus.") {
    return GetCorpus(shard_index, name_prefix).size();
  }
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_INTERNAL_TEST_UTIL_H_
