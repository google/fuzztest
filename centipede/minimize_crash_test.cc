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
#include <system_error>  // NOLINT
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/nullability.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/random.h"
#include "absl/types/span.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/environment.h"
#include "./centipede/runner_result.h"
#include "./centipede/stop.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"
#include "./common/defs.h"
#include "./common/logging.h"
#include "./common/test_util.h"

namespace fuzztest::internal {
namespace {

using ::testing::UnorderedElementsAre;

// A mock for CentipedeCallbacks.
class MinimizerMock : public CentipedeCallbacks {
 public:
  MinimizerMock(const Environment& env)
      : CentipedeCallbacks(env, internal_stop_condition_) {}

  // Runs FuzzMe() on every input, imitates failure if FuzzMe() returns true.
  bool Execute(std::string_view binary, absl::Span<const ByteSpan> inputs,
               BatchResult& batch_result) override {
    batch_result.ClearAndResize(inputs.size());
    for (auto input : inputs) {
      if (FuzzMe(input)) {
        batch_result.exit_code() = EXIT_FAILURE;
        // Set signature differently to test signature matching behavior.
        batch_result.failure_signature() =
            input[0] == 'f' ? "signature one" : "signature two";
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

  StopCondition internal_stop_condition_;
};

// Factory that creates/destroys MinimizerMock.
class MinimizerMockFactory : public CentipedeCallbacksFactory {
 public:
  CentipedeCallbacks* absl_nonnull create(
      const Environment& env, StopCondition& stop_condition) override {
    return new MinimizerMock(env);
  }
  void destroy(CentipedeCallbacks *cb) override { delete cb; }
};

TEST(MinimizeTest, FailsWhenCrasherCannotBeMinimized) {
  TempDir tmp_dir{test_info_->name()};
  Environment env;
  env.workdir = tmp_dir.path();
  env.num_runs = 100000;
  const WorkDir wd{env};
  MinimizerMockFactory factory;
  StopCondition stop_condition;
  StopCondition::StopRequest stop_request;

  const ByteArray expected_minimized = {'f'};
  stop_request = {};
  EXPECT_FALSE(MinimizeCrash(expected_minimized, env, factory, "signature one",
                             stop_condition)
                   .has_value());
  EXPECT_FALSE(stop_condition.StopRequested());
}

TEST(MinimizeTest, FailsWhenSignatureDoesNotMatch) {
  TempDir tmp_dir{test_info_->name()};
  Environment env;
  env.workdir = tmp_dir.path();
  env.num_runs = 100000;
  const WorkDir wd{env};
  MinimizerMockFactory factory;
  StopCondition stop_condition;
  StopCondition::StopRequest stop_request;

  ByteArray original_crasher = {'f', 'f', 'f', 'f', 'f', 'f',
                                'z', 'z', 'z', 'z', 'z', 'z'};
  stop_request = {};
  EXPECT_FALSE(MinimizeCrash(original_crasher, env, factory, "bad signature",
                             stop_condition)
                   .has_value());
  EXPECT_FALSE(stop_condition.StopRequested());
}

TEST(MinimizeTest, MinimizesWithSignature) {
  TempDir tmp_dir{test_info_->name()};
  Environment env;
  env.workdir = tmp_dir.path();
  env.num_runs = 100000;
  const WorkDir wd{env};
  const auto output_dir = wd.CrashReproducerDirPaths().MyShard();
  MinimizerMockFactory factory;

  ByteArray original_crasher = {'f', 'f', 'f', 'f', 'f', 'f',
                                'z', 'z', 'z', 'z', 'z', 'z'};
  constexpr size_t kNumTrials = 30;
  absl::BitGen rng;
  absl::flat_hash_set<ByteArray> minimized_crashers;
  StopCondition stop_condition;
  for (size_t i = 0; i < kNumTrials; ++i) {
    env.seed = rng();
    auto result = MinimizeCrash(original_crasher, env, factory, "signature one",
                                stop_condition);
    EXPECT_TRUE(result.has_value());
    EXPECT_FALSE(stop_condition.StopRequested());
    minimized_crashers.insert(std::move(result->input));
  }
  EXPECT_THAT(minimized_crashers, UnorderedElementsAre(ByteArray{'f'}));

  std::error_code ec;
  std::filesystem::remove_all(output_dir, ec);
  FUZZTEST_CHECK(!ec) << "Failed to clean up output dir for test "
                      << test_info_->name();
  std::filesystem::create_directory(output_dir, ec);
  FUZZTEST_CHECK(!ec) << "Failed to re-create output dir for test "
                      << test_info_->name();

  minimized_crashers.clear();
  ByteArray original_crasher_alt = {'z', 'z', 'z', 'z', 'z', 'z',
                                    'f', 'f', 'f', 'f', 'f', 'f'};
  for (size_t i = 0; i < kNumTrials; ++i) {
    env.seed = rng();
    auto result = MinimizeCrash(original_crasher_alt, env, factory,
                                "signature two", stop_condition);
    EXPECT_TRUE(result.has_value());
    EXPECT_FALSE(stop_condition.StopRequested());
    minimized_crashers.insert(std::move(result->input));
  }
  EXPECT_THAT(minimized_crashers, UnorderedElementsAre(ByteArray{'z'}));
}

}  // namespace
}  // namespace fuzztest::internal
