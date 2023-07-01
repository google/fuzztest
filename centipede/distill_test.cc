// Copyright 2023 The Centipede Authors.
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

#include "./centipede/distill.h"

#include <filesystem>  // NOLINT
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/flags/reflection.h"
#include "./centipede/blob_file.h"
#include "./centipede/defs.h"
#include "./centipede/environment.h"
#include "./centipede/feature.h"
#include "./centipede/test_util.h"

ABSL_DECLARE_FLAG(std::string, binary_hash);
ABSL_DECLARE_FLAG(std::string, binary);
ABSL_DECLARE_FLAG(std::string, workdir);

namespace centipede {
namespace {

struct TestCorpusRecord {
  ByteArray input;
  FeatureVec feature_vec;
};

using Shard = std::vector<TestCorpusRecord>;
using ShardVec = std::vector<Shard>;
using InputVec = std::vector<ByteArray>;

// Writes `record` to shard `shard_index`.
void WriteToShard(const Environment &env, const TestCorpusRecord &record,
                  size_t shard_index) {
  auto corpus_path = env.MakeCorpusPath(shard_index);
  auto features_path = env.MakeFeaturesPath(shard_index);
  const auto corpus_appender = DefaultBlobFileWriterFactory();
  const auto features_appender = DefaultBlobFileWriterFactory();
  CHECK_OK(corpus_appender->Open(corpus_path, "a"));
  CHECK_OK(features_appender->Open(features_path, "a"));
  CHECK_OK(corpus_appender->Write(record.input));
  CHECK_OK(features_appender->Write(
      PackFeaturesAndHash(record.input, record.feature_vec)));
}

// Reads and returns the distilled corpus from `env.MakeDistilledPath()`.
std::vector<ByteArray> ReadFromDistilled(const Environment &env) {
  auto distilled_path = env.MakeDistilledPath();
  auto reader = DefaultBlobFileReaderFactory();
  CHECK_OK(reader->Open(distilled_path));
  absl::Span<uint8_t> blob;
  std::vector<ByteArray> result;
  while (reader->Read(blob).ok()) {
    result.emplace_back(blob.begin(), blob.end());
  }
  return result;
}

// Distills `shards` in the order specified by `shard_indices`,
// returns the distilled corpus as a vector of inputs.
InputVec TestDistill(const ShardVec &shards,
                     const std::vector<size_t> &shard_indices,
                     std::string_view test_name) {
  // Set up the environment.
  // We need to set at least --binary_hash before `env` is constructed,
  // so we do this by overriding the flags.
  absl::FlagSaver flag_saver;
  std::string dir = std::filesystem::path(GetTestTempDir()).append(test_name);
  std::filesystem::remove_all(dir);
  std::filesystem::create_directories(dir);
  absl::SetFlag(&FLAGS_workdir, dir);
  absl::SetFlag(&FLAGS_binary, "binary_that_is_not_here");
  absl::SetFlag(&FLAGS_binary_hash, "01234567890");
  Environment env;
  env.total_shards = shards.size();
  env.my_shard_index = 1;  // an arbitrary shard index.
  std::filesystem::create_directories(env.MakeCoverageDirPath());

  // Write the shards.
  for (size_t shard_index = 0; shard_index < shards.size(); ++shard_index) {
    for (const auto &record : shards[shard_index]) {
      WriteToShard(env, record, shard_index);
    }
  }
  // Distill.
  DistillTask(env, shard_indices);
  // Read the result back.
  return ReadFromDistilled(env);
}

TEST(Distill, BasicDistill) {
  ByteArray in0 = {0};
  ByteArray in1 = {1};
  ByteArray in2 = {2};
  ByteArray in3 = {3};
  ShardVec shards = {
      // shard 0; note: distillation iterates the shards backwards.
      {{in3, {10}}, {in0, {10, 20}}},
      // shard 1
      {{in1, {20, 30}}},
      // shard 2
      {{in2, {30, 40}}},
  };
  // Distill these 3 shards in different orders, observe different results.
  EXPECT_THAT(TestDistill(shards, {0, 1, 2}, test_info_->name()),
              testing::ElementsAreArray({in0, in1, in2}));
  EXPECT_THAT(TestDistill(shards, {2, 0, 1}, test_info_->name()),
              testing::ElementsAreArray({in2, in0}));
  EXPECT_THAT(TestDistill(shards, {1, 0, 2}, test_info_->name()),
              testing::ElementsAreArray({in1, in0, in2}));
}

// TODO(kcc): add more tests once we settle on the testing code above.

}  // namespace
}  // namespace centipede
