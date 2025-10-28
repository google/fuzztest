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
        return false;
      }
      ++batch_result.num_outputs_read();
    }
    return true;
  }

 private:
  // Returns true on inputs that look like 'f???u???z', false otherwise.
  // The minimal input on which this function returns true is 'fuz'.
  bool FuzzMe(ByteSpan data) {
    if (data.empty()) return false;
    if (data.front() == 'f' && data[data.size() / 2] == 'u' &&
        data.back() == 'z') {
      return true;
    }
    return false;
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

  ByteArray expected_minimized = {'f', 'u', 'z'};

  // Test with a crashy input that can't be minimized further.
  const auto already_minimum_minimize_result =
      MinimizeCrash(expected_minimized, env, factory,
                    /*crash_signature=*/nullptr, output_dir);
  EXPECT_FALSE(already_minimum_minimize_result.ok());
  EXPECT_THAT(already_minimum_minimize_result.status().message(),
              HasSubstr("no minimized crash found"));

  // Test the actual minimization.
  ByteArray original_crasher = {'f', '.', '.', '.', '.', '.', '.', '.',
                                '.', '.', '.', 'u', '.', '.', '.', '.',
                                '.', '.', '.', '.', '.', '.', 'z'};
  EXPECT_OK(MinimizeCrash(original_crasher, env, factory,
                          /*crash_signature=*/nullptr, output_dir)
                .status());
  // Collect the new crashers from the crasher dir.
  std::vector<ByteArray> crashers;
  for (auto const& dir_entry :
       std::filesystem::directory_iterator{output_dir}) {
    ByteArray crasher;
    const std::string &path = dir_entry.path();
    ReadFromLocalFile(path, crasher);
    EXPECT_LT(crasher.size(), original_crasher.size());
    crashers.push_back(crasher);
  }
  EXPECT_THAT(crashers, testing::Contains(expected_minimized));
}

}  // namespace
}  // namespace fuzztest::internal
