// Copyright 2026 Google LLC
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

// Tests for `CreateFuzzTestAdapterManager()` in the runner interface.
//
// This is separated from other engine tests because linking the runner brings
// in its process-global state.

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/cleanup/cleanup.h"
#include "absl/strings/str_cat.h"
#include "./centipede/engine_abi.h"
#include "./centipede/environment.h"
#include "./centipede/execution_metadata.h"
#include "./centipede/in_process_centipede_callbacks.h"
#include "./centipede/mutation_data.h"
#include "./centipede/runner_interface.h"
#include "./centipede/runner_result.h"
#include "./centipede/stop.h"
#include "./common/defs.h"

namespace fuzztest::internal {
namespace {

using ::testing::SizeIs;

ByteArray ToByteArray(std::string_view sv) {
  return ByteArray(sv.begin(), sv.end());
}

std::string ToString(ByteSpan span) {
  return std::string(reinterpret_cast<const char*>(span.data()), span.size());
}

class FakeRunnerCallbacks : public RunnerCallbacks {
 public:
  bool Execute(void* input) override {
    const auto& str = *reinterpret_cast<const std::string*>(input);
    if (str == "crash_me") {
      CentipedeSetFailureDescription("runner_callbacks_crash");
    }
    return true;
  }

  void GetPresetSeedInputs(
      const std::function<void(void*)>& seed_callback) override {
    seed_callback(new std::string("runner_seed"));
  }

  void* GetRandomSeedInput() override {
    return new std::string(absl::StrCat("runner_random_", next_seed_++));
  }

  bool HasCustomMutator() const override { return true; }

  void* Mutate(void* origin,
               const ExecutionMetadata& origin_metadata) override {
    const auto& str = *reinterpret_cast<const std::string*>(origin);
    return new std::string(absl::StrCat(str, "_mut"));
  }

  void* CrossOver(void* origin, const ExecutionMetadata& origin_metadata,
                  void* other,
                  const ExecutionMetadata& other_metadata) override {
    const auto& str1 = *reinterpret_cast<const std::string*>(origin);
    const auto& str2 = *reinterpret_cast<const std::string*>(other);
    return new std::string(absl::StrCat(str1, "+", str2));
  }

  void SerializeInput(
      void* input, const std::function<void(ByteSpan)>& bytes_sink) override {
    const auto& str = *reinterpret_cast<const std::string*>(input);
    bytes_sink({reinterpret_cast<const uint8_t*>(str.data()), str.size()});
  }

  void* DeserializeInput(ByteSpan bytes) override {
    return new std::string(reinterpret_cast<const char*>(bytes.data()),
                           bytes.size());
  }

  void FreeInput(void* input) override {
    delete reinterpret_cast<std::string*>(input);
  }

 private:
  int next_seed_ = 0;
};

TEST(CreateFuzzTestAdapterManagerTest, WorksWithInProcessCentipedeCallbacks) {
  // Disable tracing outside of the input executions, as required by
  // `CreateFuzzTestAdapterManager()`.
  const int old_traced = CentipedeSetCurrentThreadTraced(/*traced=*/0);
  const absl::Cleanup tracing_restorer = [old_traced] {
    CentipedeSetCurrentThreadTraced(old_traced);
  };

  FakeRunnerCallbacks runner_callbacks;
  const FuzzTestAdapterManager manager =
      CreateFuzzTestAdapterManager(&runner_callbacks);

  Environment env;
  env.test_name = "some_test";
  env.crossover_level = 0;
  StopCondition stop_condition;
  InProcessCentipedeCallbacks callbacks(env, stop_condition, &manager);

  std::vector<ByteArray> seeds;
  EXPECT_EQ(callbacks.GetSeeds(/*num_seeds=*/2, seeds), 32);
  ASSERT_THAT(seeds, SizeIs(2));
  EXPECT_EQ(ToString(seeds[0]), "runner_seed");
  EXPECT_EQ(ToString(seeds[1]), "runner_random_0");

  std::vector<MutationInputRef> mutation_inputs = {{seeds[0], nullptr}};
  std::vector<Mutant> mutants =
      callbacks.Mutate(mutation_inputs, /*num_mutants=*/1);
  ASSERT_THAT(mutants, SizeIs(1));
  EXPECT_EQ(ToString(mutants[0].data), "runner_seed_mut");

  BatchResult batch_result;
  EXPECT_TRUE(callbacks.Execute("binary", {seeds[0]}, batch_result));
  EXPECT_EQ(batch_result.num_outputs_read(), 1);

  EXPECT_FALSE(
      callbacks.Execute("binary", {ToByteArray("crash_me")}, batch_result));
  EXPECT_EQ(batch_result.failure_description(), "runner_callbacks_crash");
}

}  // namespace
}  // namespace fuzztest::internal
