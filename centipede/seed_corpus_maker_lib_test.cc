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

#include "./centipede/seed_corpus_maker_lib.h"

#include <unistd.h>

#include <cmath>
#include <cstddef>
#include <filesystem>  // NOLINT
#include <string>
#include <string_view>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/strings/substitute.h"
#include "./centipede/feature.h"
#include "./centipede/logging.h"  // IWYU pragma: keep
#include "./centipede/seed_corpus_config.pb.h"
#include "./centipede/test_util.h"
#include "./centipede/workdir.h"
#include "google/protobuf/text_format.h"

namespace centipede {
namespace {

namespace fs = std::filesystem;
using google::protobuf::TextFormat;
using testing::IsSubsetOf;

inline constexpr auto kIdxDigits = WorkDir::kDigitsInShardIndex;

enum ShardType { kNormal, kDistilled };

SeedCorpusConfig ParseSeedCorpusConfig(std::string_view config_str) {
  SeedCorpusConfig config;
  CHECK(TextFormat::ParseFromString(config_str, &config));
  return config;
}

std::string PrintSeedCorpusConfigToString(const SeedCorpusConfig& config) {
  std::string config_str;
  TextFormat::PrintToString(config, &config_str);
  return config_str;
}

void VerifyShardsExist(            //
    std::string_view workdir,      //
    std::string_view binary_name,  //
    std::string_view binary_hash,  //
    size_t num_shards,             //
    ShardType shard_type) {
  const WorkDir wd{
      std::string{workdir},
      std::string{binary_name},
      std::string{binary_hash},
      /*my_shard_index=*/0,
  };
  const WorkDir::ShardedFileInfo corpus_files =
      shard_type == kNormal ? wd.CorpusFiles() : wd.DistilledCorpusFiles();
  const WorkDir::ShardedFileInfo features_files =
      shard_type == kNormal ? wd.FeaturesFiles() : wd.DistilledFeaturesFiles();
  for (int shard = 0; shard < num_shards + 2; ++shard) {
    if (shard < num_shards) {
      ASSERT_TRUE(fs::exists(corpus_files.ShardPath(shard)))
          << VV(shard) << VV(corpus_files.ShardPath(shard));
      ASSERT_TRUE(fs::exists(features_files.ShardPath(shard)))
          << VV(shard) << VV(features_files.ShardPath(shard));
    } else {
      ASSERT_FALSE(fs::exists(corpus_files.ShardPath(shard)))
          << VV(shard) << VV(corpus_files.ShardPath(shard));
      ASSERT_FALSE(fs::exists(features_files.ShardPath(shard)))
          << VV(shard) << VV(features_files.ShardPath(shard));
    }
  }
}

void VerifyDumpedConfig(           //
    std::string_view workdir,      //
    std::string_view binary_name,  //
    std::string_view binary_hash) {
  const WorkDir wd{
      std::string{workdir},
      std::string{binary_name},
      std::string{binary_hash},
      /*my_shard_index=*/0,
  };
  // TODO(ussuri): Verify the contents is as expected as well.
  ASSERT_TRUE(fs::exists(fs::path{wd.DebugInfoDirPath()} / "seeding.cfg"))
      << VV(workdir);
}

TEST(SeedCorpusMakerLibTest, ResolveConfig) {
  const std::string test_dir = fs::canonical(GetTestTempDir());

  // `ResolveSeedCorpusConfig()` should use the CWD to resolve relative paths.
  chdir(test_dir.c_str());

  constexpr size_t kNumShards = 3;
  constexpr std::string_view kSrcSubDir = "src/dir";
  constexpr std::string_view kDstSubDir = "dest/dir";
  const std::string_view kConfigStr = R"pb(
    sources {
      dir_glob: "./$0"
      shard_rel_glob: "corpus.*"
      num_recent_dirs: 1
      sampled_fraction: 0.5
    }
    destination {
      #
      dir_path: "./$1"
      shard_rel_glob: "corpus.*"
      num_shards: $2
    }
  )pb";
  const std::string_view kExpectedConfigStr = R"pb(
    sources {
      dir_glob: "$0/./$1"
      shard_rel_glob: "corpus.*"
      num_recent_dirs: 1
      sampled_fraction: 0.5
    }
    destination {
      dir_path: "$0/./$2"
      shard_rel_glob: "corpus.*"
      num_shards: $3
      shard_index_digits: $4
    }
  )pb";

  const SeedCorpusConfig resolved_config = ResolveSeedCorpusConfig(  //
      absl::Substitute(kConfigStr, kSrcSubDir, kDstSubDir, kNumShards));

  const SeedCorpusConfig expected_config = ParseSeedCorpusConfig(  //
      absl::Substitute(kExpectedConfigStr, test_dir, kSrcSubDir, kDstSubDir,
                       kNumShards, kIdxDigits));

  ASSERT_EQ(PrintSeedCorpusConfigToString(resolved_config),
            PrintSeedCorpusConfigToString(expected_config));
}

TEST(SeedCorpusMakerLibTest, RoundTripWriteReadWrite) {
  const fs::path test_dir = fs::canonical(GetTestTempDir());
  // `ResolveSeedCorpusConfig()` should use the CWD to resolve relative paths.
  chdir(test_dir.c_str());

  const InputAndFeaturesVec kElements = {
      {{0}, {}},
      {{1}, {feature_domains::kNoFeature}},
      {{0, 1}, {0x11, 0x23}},
      {{1, 2, 3}, {0x11, 0x23, 0xfe}},
      {{3, 4, 5, 6}, {0x111, 0x234, 0x345, 0x56}},
      {{5, 6, 7, 9}, {0x1111, 0x2345, 0x3456, 0x5678}},
      {{7, 8, 9, 10, 111}, {0x11111, 0x23456, 0x34567, 0x56789, 0xffaf}},
  };
  constexpr std::string_view kCovBin = "bin";
  constexpr std::string_view kCovHash = "hash";
  constexpr std::string_view kRelDir1 = "dir/foo";
  constexpr std::string_view kRelDir2 = "dir/bar";
  constexpr std::string_view kRelDir3 = "dir/kuq";

  // Test `WriteSeedCorpusElementsToDestination()`. This also creates a seed
  // source for the subsequent tests.
  {
    constexpr size_t kNumShards = 2;
    constexpr std::string_view kConfigStr = R"pb(
      destination {
        dir_path: "./$0"
        shard_rel_glob: "distilled-$1.*"
        num_shards: $2
        shard_index_digits: $3
      }
    )pb";
    const SeedCorpusConfig config = ParseSeedCorpusConfig(absl::Substitute(
        kConfigStr, kRelDir1, kCovBin, kNumShards, kIdxDigits));
    WriteSeedCorpusElementsToDestination(  //
        kElements, kCovBin, kCovHash, config.destination());
    const std::string workdir = (test_dir / kRelDir1).c_str();
    ASSERT_NO_FATAL_FAILURE(VerifyShardsExist(  //
        workdir, kCovBin, kCovHash, kNumShards, ShardType::kDistilled));
  }

  // Test that `SampleSeedCorpusElementsFromSource()` correctly reads a
  // subsample of elements from the seed source created by the previous step.
  {
    constexpr std::string_view kConfigStr = R"pb(
      sources {
        dir_glob: "./$0"
        shard_rel_glob: "distilled-$1.*"
        num_recent_dirs: 2  # Intentionally specify more than we actually have
        sampled_fraction: $2
      }
    )pb";

    for (const double fraction : {1.0, 0.5, 0.2}) {
      const SeedCorpusConfig config = ParseSeedCorpusConfig(
          absl::Substitute(kConfigStr, kRelDir1, kCovBin, fraction));
      InputAndFeaturesVec elements;
      SampleSeedCorpusElementsFromSource(  //
          config.sources(0), kCovBin, kCovHash, elements);
      // NOTE: 1.0 has a precise double representation, so `==` is fine.
      ASSERT_EQ(elements.size(), std::llrint(kElements.size() * fraction))
          << VV(fraction);
      ASSERT_THAT(elements, IsSubsetOf(kElements)) << VV(fraction);
    }
  }

  // Test that `GenerateSeedCorpusFromConfig()` correctly samples seed elements
  // from the source and writes expected shards to the destination.
  {
    constexpr size_t kNumShards = 3;
    constexpr std::string_view kConfigStr = R"pb(
      sources {
        dir_glob: "./$0"
        shard_rel_glob: "distilled-$1.*"
        num_recent_dirs: 1
        sampled_fraction: 1.0
      }
      destination {
        dir_path: "./$2"
        shard_rel_glob: "corpus.*"
        num_shards: $3
        shard_index_digits: $4
      }
    )pb";

    const std::string config_str = absl::Substitute(  //
        kConfigStr, kRelDir1, kCovBin, kRelDir2, kNumShards, kIdxDigits);

    {
      GenerateSeedCorpusFromConfig(  //
          config_str, kCovBin, kCovHash, "");
      const std::string workdir = (test_dir / kRelDir2).c_str();
      ASSERT_NO_FATAL_FAILURE(VerifyDumpedConfig(workdir, kCovBin, kCovHash));
      ASSERT_NO_FATAL_FAILURE(VerifyShardsExist(  //
          workdir, kCovBin, kCovHash, kNumShards, ShardType::kNormal));
    }

    {
      GenerateSeedCorpusFromConfig(  //
          config_str, kCovBin, kCovHash, kRelDir3);
      const std::string workdir = (test_dir / kRelDir3).c_str();
      ASSERT_NO_FATAL_FAILURE(VerifyDumpedConfig(workdir, kCovBin, kCovHash));
      ASSERT_NO_FATAL_FAILURE(VerifyShardsExist(  //
          workdir, kCovBin, kCovHash, kNumShards, ShardType::kNormal));
    }
  }
}

}  // namespace
}  // namespace centipede
