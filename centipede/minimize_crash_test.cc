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

#include <cstddef>
#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>

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
#include "./common/defs.h"
#include "./common/test_util.h"

namespace fuzztest::internal {
namespace {

using ::testing::UnorderedElementsAre;

// A mock for CentipedeCallbacks.
class MinimizerMock : public CentipedeCallbacks {
 public:
  MinimizerMock(const Environment& env, StopCondition& stop_condition,
                size_t crash_on_attempt = 1)
      : CentipedeCallbacks(env, stop_condition),
        crash_on_attempt_(crash_on_attempt) {}

  // Runs FuzzMe() on every input, imitates failure if FuzzMe() returns true
  // `crash_on_attempt_` consecutive times on the same input.
  bool Execute(std::string_view binary, absl::Span<const ByteSpan> inputs,
               BatchResult& batch_result) override {
    EXPECT_LE(inputs.size(), env_.batch_size);
    batch_result.ClearAndResize(inputs.size());
    for (size_t i = 0; i < inputs.size(); ++i) {
      const auto& input = inputs[i];
      if (input.data() == last_input_.data() &&
          input.size() == last_input_.size()) {
        ++current_attempts_;
      } else {
        last_input_ = input;
        current_attempts_ = 1;
      }
      if (FuzzMe(input) && current_attempts_ >= crash_on_attempt_) {
        batch_result.exit_code() = EXIT_FAILURE;
        // Set signature differently to test signature matching behavior.
        batch_result.failure_signature() =
            input[0] == 'f' ? "signature one" : "signature two";
        batch_result.failure_description() =
            input[0] == 'f' ? "description one" : "description two";
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

  size_t crash_on_attempt_ = 1;
  ByteSpan last_input_;
  size_t current_attempts_ = 0;
};

// Factory that creates/destroys MinimizerMock.
class MinimizerMockFactory : public CentipedeCallbacksFactory {
 public:
  explicit MinimizerMockFactory(size_t crash_on_attempt = 1)
      : crash_on_attempt_(crash_on_attempt) {}

  CentipedeCallbacks* absl_nonnull create(
      const Environment& env, StopCondition& stop_condition) override {
    return new MinimizerMock(env, stop_condition, crash_on_attempt_);
  }
  void destroy(CentipedeCallbacks *cb) override { delete cb; }

 private:
  size_t crash_on_attempt_ = 1;
};

TEST(MinimizeTest, FailsWhenCrasherCannotBeMinimized) {
  Environment env;
  env.num_runs = 100000;
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
  Environment env;
  env.num_runs = 100000;
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
  env.num_runs = 100000;
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
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->description, "description one");
    EXPECT_FALSE(stop_condition.StopRequested());
    minimized_crashers.insert(std::move(result->input));
  }
  EXPECT_THAT(minimized_crashers, UnorderedElementsAre(ByteArray{'f'}));

  minimized_crashers.clear();
  ByteArray original_crasher_alt = {'z', 'z', 'z', 'z', 'z', 'z',
                                    'f', 'f', 'f', 'f', 'f', 'f'};
  for (size_t i = 0; i < kNumTrials; ++i) {
    env.seed = rng();
    auto result = MinimizeCrash(original_crasher_alt, env, factory,
                                "signature two", stop_condition);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->description, "description two");
    EXPECT_FALSE(stop_condition.StopRequested());
    minimized_crashers.insert(std::move(result->input));
  }
  EXPECT_THAT(minimized_crashers, UnorderedElementsAre(ByteArray{'z'}));
}

TEST(MinimizeTest, MinimizesWithReplayCrashAttempts) {
  Environment env;
  env.num_runs = 100000;
  MinimizerMockFactory factory(/*crash_on_attempt=*/3);
  StopCondition stop_condition;

  ByteArray original_crasher = {'f', 'f', 'f', 'f', 'f', 'f',
                                'z', 'z', 'z', 'z', 'z', 'z'};
  env.replay_crash_attempts = 2;
  EXPECT_FALSE(MinimizeCrash(original_crasher, env, factory, "signature one",
                             stop_condition)
                   .has_value());

  env.replay_crash_attempts = 3;
  auto result = MinimizeCrash(original_crasher, env, factory, "signature one",
                              stop_condition);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->input, ByteArray{'f'});
  EXPECT_EQ(result->description, "description one");
  EXPECT_FALSE(stop_condition.StopRequested());
}

}  // namespace
}  // namespace fuzztest::internal
