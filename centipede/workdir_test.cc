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

#include <array>
#include <string_view>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "./centipede/environment.h"

namespace centipede {

TEST(WorkDirTest, Main) {
  Environment env{};
  env.workdir = "/dir";
  env.binary_name = "bin";
  env.binary_hash = "hash";
  env.my_shard_index = 3;

  const std::array<WorkDir, 2> wds = {
      WorkDir{"/dir", "bin", "hash", 3},
      WorkDir{env},
  };

  for (int i = 0; i < wds.size(); ++i) {
    SCOPED_TRACE(absl::StrCat("Test case ", i));
    const WorkDir& wd = wds[i];

    EXPECT_EQ(wd.CoverageDirPath(), "/dir/bin-hash");
    EXPECT_EQ(wd.CrashReproducerDirPath(), "/dir/crashes");
    EXPECT_EQ(wd.BinaryInfoDirPath(), "/dir/bin-hash/binary-info");

    EXPECT_EQ(wd.CorpusPath(), "/dir/corpus.000003");
    EXPECT_EQ(wd.CorpusPath(7), "/dir/corpus.000007");
    EXPECT_EQ(wd.DistilledCorpusPath(), "/dir/distilled-bin.000003");

    EXPECT_EQ(wd.FeaturesPath(), "/dir/bin-hash/features.000003");
    EXPECT_EQ(wd.FeaturesPath(7), "/dir/bin-hash/features.000007");
    EXPECT_EQ(wd.DistilledFeaturesPath(),
              "/dir/bin-hash/distilled-features-bin.000003");

    EXPECT_EQ(wd.CoverageReportPath(),  //
              "/dir/coverage-report-bin.000003.txt");
    EXPECT_EQ(wd.CoverageReportPath("anno"),
              "/dir/coverage-report-bin.000003.anno.txt");
    EXPECT_EQ(wd.SourceBasedCoverageReportPath(),
              "/dir/source-coverage-report-bin.000003");
    EXPECT_EQ(wd.SourceBasedCoverageReportPath("anno"),
              "/dir/source-coverage-report-bin.000003.anno");
    EXPECT_EQ(wd.SourceBasedCoverageRawProfilePath(),
              "/dir/bin-hash/clang_coverage.000003.%m.profraw");
    EXPECT_EQ(wd.SourceBasedCoverageIndexedProfilePath(),
              "/dir/bin-hash/clang_coverage.profdata");
    // TODO(ussuri): Test `EnumerateRawCoverageProfiles()`.

    EXPECT_EQ(wd.CorpusStatsPath(),  //
              "/dir/corpus-stats-bin.000003.json");
    EXPECT_EQ(wd.CorpusStatsPath("anno"),  //
              "/dir/corpus-stats-bin.000003.anno.json");
    EXPECT_EQ(wd.CoverageReportPath(),  //
              "/dir/coverage-report-bin.000003.txt");
    EXPECT_EQ(wd.CoverageReportPath("anno"),  //
              "/dir/coverage-report-bin.000003.anno.txt");
    EXPECT_EQ(wd.FuzzingStatsPath(),  //
              "/dir/fuzzing-stats-bin.000003.csv");
    EXPECT_EQ(wd.FuzzingStatsPath("anno"),  //
              "/dir/fuzzing-stats-bin.000003.anno.csv");
    EXPECT_EQ(wd.RUsageReportPath(),  //
              "/dir/rusage-report-bin.000003.txt");
    EXPECT_EQ(wd.RUsageReportPath("anno"),  //
              "/dir/rusage-report-bin.000003.anno.txt");
    EXPECT_EQ(wd.RUsageReportPath(),  //
              "/dir/rusage-report-bin.000003.txt");
    EXPECT_EQ(wd.RUsageReportPath("anno"),  //
              "/dir/rusage-report-bin.000003.anno.txt");
  }
}

}  // namespace centipede
