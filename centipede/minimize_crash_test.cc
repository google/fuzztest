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

#include "./centipede/minimize_crash.h"

#include <cstdlib>
#include <filesystem>  // NOLINT
#include <string>
#include <string_view>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/nullability.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/random.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/environment.h"
#include "./centipede/runner_result.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"
#include "./common/defs.h"
#include "./common/test_util.h"

namespace fuzztest::internal {
namespace {

using ::testing::HasSubstr;
using ::testing::UnorderedElementsAre;

// A mock for CentipedeCallbacks.
class MinimizerMock : public CentipedeCallbacks {
 public:
  MinimizerMock(const Environment &env) : CentipedeCallbacks(env) {}

  // Runs FuzzMe() on every input, imitates failure if FuzzMe() returns true.
  bool Execute(std::string_view binary, const std::vector<ByteArray> &inputs,
               BatchResult &batch_result) override {
    batch_result.ClearAndResize(inputs.size());
    for (auto &input : inputs) {
      if (FuzzMe(input)) {
        batch_result.exit_code() = EXIT_FAILURE;
        // Set signature differently to test signature matching behavior.
        batch_result.failure_signature() =
            input[0] == 'f' ? "first type" : "second type";
        return false;
      }
      ++batch_result.num_outputs_read();
    }
    return true;
  }

 private:
  // Returns true on inputs that look like '[fz]+', false otherwise.
  // The minimal input on which this function returns true is 'f' or 'z', with
  // different crash signatures.
  bool FuzzMe(ByteSpan data) {
    if (data.empty()) return false;
    for (const auto c : data) {
      if (c != 'f' && c != 'z') return false;
    }
    return true;
  }
};

// Factory that creates/destroys MinimizerMock.
class MinimizerMockFactory : public CentipedeCallbacksFactory {
 public:
  CentipedeCallbacks *absl_nonnull create(const Environment &env) override {
    return new MinimizerMock(env);
  }
  void destroy(CentipedeCallbacks *cb) override { delete cb; }
};

TEST(MinimizeTest, MinimizeTest) {
  TempDir tmp_dir{test_info_->name()};
  Environment env;
  env.workdir = tmp_dir.path();
  env.num_runs = 100000;
  const WorkDir wd{env};
  const auto output_dir = wd.CrashReproducerDirPaths().MyShard();
  MinimizerMockFactory factory;

  // Test with a non-crashy input.
  const auto non_crashy_minimize_result = MinimizeCrash(
      {1, 2, 3}, env, factory, /*crash_signature=*/nullptr, output_dir);
  EXPECT_FALSE(non_crashy_minimize_result.ok());
  EXPECT_THAT(non_crashy_minimize_result.status().message(),
              HasSubstr("did not crash"));

  const ByteArray expected_minimized = {'f'};
  const ByteArray expected_minimized_alt = {'z'};

  // Test with a crashy input that can't be minimized further.
  const auto already_minimum_minimize_result =
      MinimizeCrash(expected_minimized, env, factory,
                    /*crash_signature=*/nullptr, output_dir);
  EXPECT_FALSE(already_minimum_minimize_result.ok());
  EXPECT_THAT(already_minimum_minimize_result.status().message(),
              HasSubstr("no minimized crash found"));

  // Test the actual minimization.
  ByteArray original_crasher = {'f', 'f', 'f', 'f', 'f', 'f',
                                'z', 'z', 'z', 'z', 'z', 'z'};

  // This is inheritly flaky but with 30 trials the failure rate should be
  // small enough (1/2^30).
  constexpr size_t kNumTrials = 30;
  absl::BitGen rng;
  absl::flat_hash_set<ByteArray> minimized_crashers;
  for (size_t i = 0; i < kNumTrials; ++i) {
    env.seed = rng();
    EXPECT_OK(MinimizeCrash(original_crasher, env, factory,
                            /*crash_signature=*/nullptr, output_dir)
                  .status());
    // Collect the new crashers from the crasher dir.
    for (auto const& dir_entry :
         std::filesystem::directory_iterator{output_dir}) {
      ByteArray crasher;
      const std::string& path = dir_entry.path();
      ReadFromLocalFile(path, crasher);
      EXPECT_LT(crasher.size(), original_crasher.size());
      minimized_crashers.insert(crasher);
    }
  }
  EXPECT_THAT(minimized_crashers,
              UnorderedElementsAre(expected_minimized, expected_minimized_alt));
}

TEST(MinimizeTest, MinimizesTestWithSignature) {
  TempDir tmp_dir{test_info_->name()};
  Environment env;
  env.workdir = tmp_dir.path();
  env.num_runs = 100000;
  env.minimize_crash_with_signature = true;
  const WorkDir wd{env};
  const auto output_dir = wd.CrashReproducerDirPaths().MyShard();
  MinimizerMockFactory factory;

  ByteArray original_crasher = {'f', 'f', 'f', 'f', 'f', 'f',
                                'z', 'z', 'z', 'z', 'z', 'z'};
  constexpr size_t kNumTrials = 30;
  absl::BitGen rng;
  absl::flat_hash_set<ByteArray> minimized_crashers;
  for (size_t i = 0; i < kNumTrials; ++i) {
    env.seed = rng();
    EXPECT_OK(MinimizeCrash(original_crasher, env, factory,
                            /*crash_signature=*/nullptr, output_dir)
                  .status());
    // Collect the new crashers from the crasher dir.
    for (auto const& dir_entry :
         std::filesystem::directory_iterator{output_dir}) {
      ByteArray crasher;
      const std::string& path = dir_entry.path();
      ReadFromLocalFile(path, crasher);
      EXPECT_LT(crasher.size(), original_crasher.size());
      minimized_crashers.insert(crasher);
    }
  }
  EXPECT_THAT(minimized_crashers, UnorderedElementsAre(ByteArray{'f'}));
}

}  // namespace
}  // namespace fuzztest::internal
