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

#include <string_view>

#include "gtest/gtest.h"
#include "./centipede/environment.h"

// TODO(b/295978603, ussuri): Add more tests. The ones below were transplanted
//  from `Environment`'s tests while factoring out `WorkDir` from it.

namespace centipede {

TEST(WorkDirTest, DistilledCorpusAndFeaturesPaths) {
  Environment env{};
  env.my_shard_index = 3;
  WorkDir wd{env};
  env.binary_name = "foo";
  env.binary_hash = "foo_hash";
  EXPECT_EQ(wd.DistilledCorpusPath(), "distilled-foo.000003");
  EXPECT_EQ(wd.DistilledFeaturesPath(),
            "foo-foo_hash/distilled-features-foo.000003");
}

TEST(WorkDirTest, CoverageReportPath) {
  // TODO(ussuri): `Environment` is not test-friendly (initialized through
  //  flags hidden in the .cc, so can't even `absl::SetFlag` them). Fix.
  Environment env{};
  WorkDir wd{env};
  EXPECT_EQ(wd.CoverageReportPath(), "coverage-report-.000000.txt");
  EXPECT_EQ(wd.CoverageReportPath("initial"),
            "coverage-report-.000000.initial.txt");
}

}  // namespace centipede
