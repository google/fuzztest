// Copyright 2024 The Centipede Authors.
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

#include "./centipede/seed_corpus_config_proto_lib.h"

#include <cstddef>
#include <sstream>

#include "gtest/gtest.h"
#include "./fuzztest/fuzztest.h"
#include "absl/log/check.h"
#include "absl/strings/substitute.h"
#include "./centipede/seed_corpus_config.pb.h"
#include "./centipede/workdir.h"
#include "./common/logging.h"  // IWYU pragma: keep
#include "./common/status_macros.h"
#include "./common/test_util.h"
#include "google/protobuf/text_format.h"
#include "google/protobuf/util/message_differencer.h"

namespace centipede {
namespace {

using ::google::protobuf::TextFormat;
using ::google::protobuf::util::DefaultFieldComparator;
using ::google::protobuf::util::MessageDifferencer;

inline constexpr auto kIdxDigits = WorkDir::kDigitsInShardIndex;

proto::SeedCorpusConfig ParseSeedCorpusConfigProto(
    std::string_view config_str) {
  proto::SeedCorpusConfig config_proto;
  CHECK(TextFormat::ParseFromString(config_str, &config_proto));
  return config_proto;
}

std::string PrintSeedCorpusConfigProtoToString(
    const proto::SeedCorpusConfig& config_proto) {
  std::string config_str;
  TextFormat::PrintToString(config_proto, &config_str);
  return config_str;
}

TEST(SeedCorpusMakerLibTest, ResolveConfig) {
  const std::string test_dir = GetTestTempDir(test_info_->name());

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

  const proto::SeedCorpusConfig resolved_config_proto =
      ValueOrDie(ResolveSeedCorpusConfigProto(  //
          absl::Substitute(kConfigStr, kSrcSubDir, kDstSubDir, kNumShards)));

  const proto::SeedCorpusConfig expected_config_proto =
      ParseSeedCorpusConfigProto(  //
          absl::Substitute(kExpectedConfigStr, test_dir, kSrcSubDir, kDstSubDir,
                           kNumShards, kIdxDigits));

  ASSERT_EQ(PrintSeedCorpusConfigProtoToString(resolved_config_proto),
            PrintSeedCorpusConfigProtoToString(expected_config_proto));
}

void SeedCorpusConfigProtoConversionRoundTrip(
    const proto::SeedCorpusConfig& config_proto) {
  std::ostringstream os;
  os << CreateSeedCorpusConfigFromProto(config_proto);
  const std::string stringified_config = os.str();
  const proto::SeedCorpusConfig parsed_config_proto =
      ParseSeedCorpusConfigProto(stringified_config);
  MessageDifferencer diff;
  diff.set_message_field_comparison(MessageDifferencer::EQUIVALENT);
  DefaultFieldComparator comparator;
  comparator.set_treat_nan_as_equal(true);
  comparator.set_float_comparison(
      DefaultFieldComparator::FloatComparison::APPROXIMATE);
  comparator.SetDefaultFractionAndMargin(0.0001, 0.0001);
  diff.set_field_comparator(&comparator);
  std::string diff_out;
  diff.ReportDifferencesToString(&diff_out);
  const bool is_equal = diff.Compare(config_proto, parsed_config_proto);
  ASSERT_TRUE(is_equal) << config_proto << " is different than "
                        << parsed_config_proto << ": " << diff_out;
}

FUZZ_TEST(SeedCorpusConfigProtoLibFuzzTest,
          SeedCorpusConfigProtoConversionRoundTrip);

}  // namespace
}  // namespace centipede
