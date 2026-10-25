// Copyright 2026 The FuzzTest Authors.
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

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/thread_annotations.h"
#include "absl/flags/marshalling.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./centipede/engine_abi.h"
#include "./centipede/engine_controller_abi.h"
#include "./centipede/environment.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"
#include "./common/defs.h"
#include "./common/hash.h"
#include "./common/test_util.h"

namespace fuzztest::internal {
namespace {

using ::testing::Contains;
using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::Not;

class ScopedEnvVar {
 public:
  ScopedEnvVar(const char* name, std::optional<std::string_view> value)
      : name_(name) {
    if (const char* prev = std::getenv(name)) {
      prev_value_ = prev;
    }
    if (value.has_value()) {
      setenv(name, std::string(*value).c_str(), /*overwrite=*/1);
    } else {
      unsetenv(name);
    }
  }

  ~ScopedEnvVar() {
    if (prev_value_.has_value()) {
      setenv(name_.c_str(), prev_value_->c_str(), /*overwrite=*/1);
    } else {
      unsetenv(name_.c_str());
    }
  }

  ScopedEnvVar(const ScopedEnvVar&) = delete;
  ScopedEnvVar& operator=(const ScopedEnvVar&) = delete;

 private:
  std::string name_;
  std::optional<std::string> prev_value_;
};

FuzzTestBytesView ToBytesView(std::string_view sv) {
  return {reinterpret_cast<const uint8_t*>(sv.data()), sv.size()};
}

ByteArray ToByteArray(std::string_view sv) {
  return ByteArray(sv.begin(), sv.end());
}

uint64_t MakeEngineFeature(uint32_t domain, uint32_t feature,
                           uint32_t counter) {
  return (static_cast<uint64_t>(domain) << kFuzzTestCoverageDomainIdStartBit) |
         (static_cast<uint64_t>(feature)
          << kFuzzTestCoverageFeatureIdStartBit) |
         counter;
}

struct FakeInput {
  std::string content;
};

struct FakeAdapterState {
  std::atomic<int> adapters_constructed{0};
  std::atomic<int> active_adapters{0};
  std::atomic<int> active_inputs{0};
  bool crash_on_mutant_3 = true;

  absl::Mutex mu;
  std::vector<std::string> executed_inputs ABSL_GUARDED_BY(mu);

  std::vector<std::string> GetExecutedInputs() {
    absl::MutexLock lock(mu);
    return executed_inputs;
  }
};

struct FakeAdapterInstance {
  FakeAdapterState* state = nullptr;
  const FuzzTestDiagnosticSink* diagnostic_sink = nullptr;
};

void EmitFakeInput(FakeAdapterState* state, std::string content,
                   const FuzzTestInputSink* sink) {
  state->active_inputs.fetch_add(1, std::memory_order_relaxed);
  sink->Emit(sink->ctx, reinterpret_cast<FuzzTestInputHandle>(
                            new FakeInput{std::move(content)}));
}

void FakeSetUpCoverageDomains(FuzzTestAdapterCtx* ctx,
                              const FuzzTestCoverageDomainRegistry* registry) {
  static constexpr std::string_view kBaseDomainName = "base";
  const FuzzTestCoverageDomain base_domain = {
      /*domain_id=*/0,
      /*name=*/ToBytesView(kBaseDomainName),
      /*feature_id_bit_size=*/27,
      /*counter_bit_size=*/0,
  };
  registry->Register(registry->ctx, &base_domain);
}

void FakeGetRandomSeedInput(FuzzTestAdapterCtx* ctx,
                            const FuzzTestInputSink* sink) {
  auto* instance = reinterpret_cast<FakeAdapterInstance*>(ctx);
  EmitFakeInput(instance->state, "random_seed", sink);
}

void FakeMutate(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input, int shrink,
                const FuzzTestInputSink* sink) {
  auto* instance = reinterpret_cast<FakeAdapterInstance*>(ctx);
  const auto* input_obj = reinterpret_cast<FakeInput*>(input);
  if (input_obj->content == "random_seed") {
    EmitFakeInput(instance->state, "mutant_1", sink);
  } else if (input_obj->content == "mutant_1") {
    EmitFakeInput(instance->state, "mutant_2", sink);
  } else if (input_obj->content == "mutant_2") {
    EmitFakeInput(instance->state, "mutant_3", sink);
  } else {
    EmitFakeInput(instance->state, absl::StrCat(input_obj->content, "_mutated"),
                  sink);
  }
}

void FakeExecute(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input,
                 const FuzzTestFeedbackSink* sink) {
  auto* instance = reinterpret_cast<FakeAdapterInstance*>(ctx);
  FakeAdapterState* state = instance->state;
  const auto* input_obj = reinterpret_cast<FakeInput*>(input);

  {
    absl::MutexLock lock(state->mu);
    state->executed_inputs.push_back(input_obj->content);
  }

  std::vector<uint64_t> features;
  if (input_obj->content == "random_seed") {
    features.push_back(MakeEngineFeature(0, 0, 0));
    features.push_back(MakeEngineFeature(0, 1, 0));
  } else if (input_obj->content == "mutant_1") {
    features.push_back(MakeEngineFeature(0, 2, 0));
  } else if (input_obj->content == "mutant_2") {
    features.push_back(MakeEngineFeature(0, 3, 0));
  } else if (input_obj->content == "mutant_3" && state->crash_on_mutant_3) {
    static constexpr std::string_view kDescription = "some_failure_description";
    static constexpr std::string_view kSignature = "some_signature";
    const auto description_view = ToBytesView(kDescription);
    const auto signature_view = ToBytesView(kSignature);
    instance->diagnostic_sink->EmitFinding(instance->diagnostic_sink->ctx,
                                           &description_view, &signature_view);
  } else {
    features.push_back(MakeEngineFeature(0, 4, 0));
  }

  const FuzzTestUint64sView features_view{features.data(), features.size()};
  sink->EmitCoverageFeatures(sink->ctx, &features_view);
}

void FakeDeserializeInputContent(FuzzTestAdapterCtx* ctx,
                                 const FuzzTestBytesView* content,
                                 const FuzzTestInputSink* sink) {
  auto* instance = reinterpret_cast<FakeAdapterInstance*>(ctx);
  EmitFakeInput(
      instance->state,
      std::string(reinterpret_cast<const char*>(content->data), content->size),
      sink);
}

void FakeSerializeInputContent(FuzzTestAdapterCtx* ctx,
                               FuzzTestInputHandle input,
                               const FuzzTestBytesSink* sink) {
  const auto* input_obj = reinterpret_cast<FakeInput*>(input);
  const FuzzTestBytesView bytes = ToBytesView(input_obj->content);
  sink->Emit(sink->ctx, &bytes);
}

void FakeFreeInput(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input) {
  auto* instance = reinterpret_cast<FakeAdapterInstance*>(ctx);
  instance->state->active_inputs.fetch_sub(1, std::memory_order_relaxed);
  delete reinterpret_cast<FakeInput*>(input);
}

void FakeFreeCtx(FuzzTestAdapterCtx* ctx) {
  auto* instance = reinterpret_cast<FakeAdapterInstance*>(ctx);
  instance->state->active_adapters.fetch_sub(1, std::memory_order_relaxed);
  delete instance;
}

FuzzTestAdapterManager MakeFakeAdapterManager(FakeAdapterState* state) {
  return {
      /*ctx=*/reinterpret_cast<FuzzTestAdapterManagerCtx*>(state),
      /*GetBinaryId=*/
      [](FuzzTestAdapterManagerCtx* ctx, const FuzzTestBytesSink* sink) {
        static constexpr std::string_view kBinaryId = "some_binary_id";
        const auto bytes = ToBytesView(kBinaryId);
        sink->Emit(sink->ctx, &bytes);
      },
      /*GetTestName=*/
      [](FuzzTestAdapterManagerCtx* ctx, const FuzzTestBytesSink* sink) {
        static constexpr std::string_view kTestName = "some_test";
        const auto bytes = ToBytesView(kTestName);
        sink->Emit(sink->ctx, &bytes);
      },
      /*ConstructAdapter=*/
      [](FuzzTestAdapterManagerCtx* ctx,
         const FuzzTestDiagnosticSink* diagnostic_sink,
         FuzzTestAdapter* adapter_out) {
        auto* state = reinterpret_cast<FakeAdapterState*>(ctx);
        state->adapters_constructed.fetch_add(1, std::memory_order_relaxed);
        state->active_adapters.fetch_add(1, std::memory_order_relaxed);
        auto* instance = new FakeAdapterInstance{state, diagnostic_sink};
        adapter_out->ctx = reinterpret_cast<FuzzTestAdapterCtx*>(instance);
        adapter_out->SetUpCoverageDomains = FakeSetUpCoverageDomains;
        adapter_out->GetPresetSeedInputs = nullptr;
        adapter_out->GetRandomSeedInput = FakeGetRandomSeedInput;
        adapter_out->Mutate = FakeMutate;
        adapter_out->CrossOver = nullptr;
        adapter_out->Execute = FakeExecute;
        adapter_out->DeserializeInputContent = FakeDeserializeInputContent;
        adapter_out->SerializeInputContent = FakeSerializeInputContent;
        adapter_out->SerializeInputMetadata = nullptr;
        adapter_out->UpdateInputMetadata = nullptr;
        adapter_out->FreeInput = FakeFreeInput;
        adapter_out->FreeCtx = FakeFreeCtx;
      },
  };
}

FuzzTestControllerStatus RunController(const FuzzTestAdapterManager* manager,
                                       const std::vector<std::string>& flags) {
  std::vector<FuzzTestBytesView> views;
  views.reserve(flags.size());
  for (const std::string& flag : flags) {
    views.push_back(ToBytesView(flag));
  }
  const FuzzTestBytesViews flags_views = {views.data(), views.size()};
  return FuzzTestControllerRun(manager, &flags_views);
}

TEST(EngineControllerTest, RunsInProcessAndFindsCrashWhenBinaryFlagIsEmpty) {
  TempDir tmp_dir("engine_controller_in_process_crash");
  FakeAdapterState state;
  const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);

  const std::string stop_at =
      absl::UnparseFlag(absl::Now() + absl::Seconds(10));
  EXPECT_EQ(
      RunController(&manager,
                    {
                        absl::StrCat("--workdir=", tmp_dir.path().string()),
                        "--test_name=some_test",
                        "--populate_binary_info=0",
                        "--exit_on_crash=1",
                        absl::StrCat("--stop_at=", stop_at),
                    }),
      kFuzzTestControllerFailure);

  EXPECT_EQ(state.adapters_constructed.load(), 1);
  EXPECT_EQ(state.active_adapters.load(), 0);
  EXPECT_EQ(state.active_inputs.load(), 0);

  Environment expected_env;
  expected_env.workdir = tmp_dir.path().string();
  expected_env.UpdateBinaryHashIfEmpty();
  const WorkDir wd{expected_env};
  const std::string crash_hash = Hash(ToByteArray("mutant_3"));
  const std::filesystem::path reproducer_path =
      std::filesystem::path(wd.CrashReproducerDirPaths().MyShard()) /
      crash_hash;
  const std::filesystem::path desc_path =
      std::filesystem::path(wd.CrashMetadataDirPaths().MyShard()) /
      absl::StrCat(crash_hash, ".desc");

  ASSERT_TRUE(std::filesystem::exists(reproducer_path));
  std::string reproducer_content;
  ReadFromLocalFile(reproducer_path.string(), reproducer_content);
  EXPECT_EQ(reproducer_content, "mutant_3");

  ASSERT_TRUE(std::filesystem::exists(desc_path));
  std::string desc_content;
  ReadFromLocalFile(desc_path.string(), desc_content);
  EXPECT_EQ(desc_content, "some_failure_description");
}

TEST(EngineControllerTest, RunsInProcessAndSucceedsWithinNumRuns) {
  TempDir tmp_dir("engine_controller_in_process_success");
  FakeAdapterState state;
  state.crash_on_mutant_3 = false;
  const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);

  EXPECT_EQ(
      RunController(&manager,
                    {
                        absl::StrCat("--workdir=", tmp_dir.path().string()),
                        "--test_name=some_test",
                        "--populate_binary_info=false",
                        "--num_runs=2",
                        "--crossover_level=0",
                    }),
      kFuzzTestControllerSuccess);

  EXPECT_EQ(state.adapters_constructed.load(), 1);
  EXPECT_EQ(state.active_adapters.load(), 0);
  EXPECT_EQ(state.active_inputs.load(), 0);
  EXPECT_THAT(state.GetExecutedInputs(), Contains("random_seed"));
}

TEST(EngineControllerTest, UsesDefaultCallbacksSubprocessWhenBinaryFlagIsSet) {
  const std::filesystem::path test_binary_path = GetDataDependencyFilepath(
      "centipede/testing/test_binary_for_engine_testing");
  const std::string stop_at =
      absl::UnparseFlag(absl::Now() + absl::Seconds(10));

  // Even when a non-null manager is passed, specifying `--binary` must run via
  // DefaultCallbacksFactory<CentipedeDefaultCallbacks> (subprocess worker)
  // rather than invoking `manager` in-process.
  {
    TempDir tmp_dir("engine_controller_subprocess_with_manager");
    FakeAdapterState state;
    const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);

    EXPECT_EQ(
        RunController(&manager,
                      {
                          absl::StrCat("--binary=", test_binary_path.string()),
                          absl::StrCat("--workdir=", tmp_dir.path().string()),
                          "--test_name=some_test",
                          "--populate_binary_info=false",
                          "--exit_on_crash=true",
                          absl::StrCat("--stop_at=", stop_at),
                      }),
        kFuzzTestControllerFailure);
    EXPECT_EQ(state.adapters_constructed.load(), 0);

    Environment expected_env;
    expected_env.workdir = tmp_dir.path().string();
    expected_env.coverage_binary = test_binary_path.string();
    expected_env.binary_name = test_binary_path.filename().string();
    expected_env.UpdateBinaryHashIfEmpty();
    const WorkDir wd{expected_env};
    const std::string crash_hash = Hash(ToByteArray("mutant_3"));
    const std::filesystem::path reproducer_path =
        std::filesystem::path(wd.CrashReproducerDirPaths().MyShard()) /
        crash_hash;
    ASSERT_TRUE(std::filesystem::exists(reproducer_path));
    std::string reproducer_content;
    ReadFromLocalFile(reproducer_path.string(), reproducer_content);
    EXPECT_EQ(reproducer_content, "mutant_3");
  }

  // Also works when `manager` is nullptr.
  {
    TempDir tmp_dir("engine_controller_subprocess_null_manager");
    EXPECT_EQ(
        RunController(/*manager=*/nullptr,
                      {
                          absl::StrCat("--binary=", test_binary_path.string()),
                          absl::StrCat("--workdir=", tmp_dir.path().string()),
                          "--test_name=some_test",
                          "--populate_binary_info=false",
                          "--exit_on_crash=true",
                          absl::StrCat("--stop_at=", stop_at),
                      }),
        kFuzzTestControllerFailure);
  }
}

TEST(EngineControllerTest,
     ParsesComplexFlagTypesAndAppliesEnvironmentPostProcessing) {
  // Verify `--j=N` post-processing spawns N shard threads.
  {
    TempDir tmp_dir("engine_controller_j_shards");
    FakeAdapterState state;
    state.crash_on_mutant_3 = false;
    const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);

    EXPECT_EQ(
        RunController(&manager,
                      {
                          absl::StrCat("--workdir=", tmp_dir.path().string()),
                          "--populate_binary_info=false",
                          "--j=3",
                          "--num_runs=1",
                      }),
        kFuzzTestControllerSuccess);
    EXPECT_EQ(state.adapters_constructed.load(), 3);
    EXPECT_TRUE(std::filesystem::exists(tmp_dir.path() / "corpus.000000"));
    EXPECT_TRUE(std::filesystem::exists(tmp_dir.path() / "corpus.000001"));
    EXPECT_TRUE(std::filesystem::exists(tmp_dir.path() / "corpus.000002"));
  }

  // Verify vector<string>, optional<bool>, absl::Duration, absl::Time, int,
  // uint64_t, and coverage_binary/binary_name/binary_hash post-processing.
  {
    TempDir tmp_dir("engine_controller_complex_flags");
    const std::string workdir = tmp_dir.CreateSubdir("workdir");
    const std::string corpus_out = tmp_dir.CreateSubdir("corpus_out");
    const std::string corpus_in = tmp_dir.CreateSubdir("corpus_in");
    WriteToLocalFile((std::filesystem::path(corpus_in) / "seed1").string(),
                     "seed_from_in_dir");

    FakeAdapterState state;
    state.crash_on_mutant_3 = false;
    const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);

    EXPECT_EQ(RunController(
                  &manager,
                  {
                      absl::StrCat("--workdir=", workdir),
                      "--coverage_binary=/fake/dir/custom_cov_bin",
                      "--binary_hash=CUSTOM_HASH",
                      absl::StrCat("--corpus_dir=", corpus_out, ",", corpus_in),
                      "--first_corpus_dir_output_only=true",
                      "--fuzztest_update_corpus_database=",
                      "--runner_cleanup_timeout=30s",
                      "--stop_at=2099-01-01T00:00:00Z",
                      "--user_feature_domain_mask=0x1",
                      "--telemetry_frequency=-2",
                      "--populate_binary_info=false",
                      "--num_runs=1",
                  }),
              kFuzzTestControllerSuccess);

    EXPECT_TRUE(std::filesystem::exists(std::filesystem::path(workdir) /
                                        "custom_cov_bin-CUSTOM_HASH"));
    EXPECT_THAT(state.GetExecutedInputs(), Contains("seed_from_in_dir"));

    std::vector<std::filesystem::path> exported_files;
    for (const auto& entry : std::filesystem::directory_iterator(corpus_out)) {
      exported_files.push_back(entry.path());
    }
    EXPECT_THAT(exported_files, Not(IsEmpty()));
  }
}

TEST(EngineControllerTest, RejectsInvalidOrUnknownFlagsGracefully) {
  FakeAdapterState state;
  const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);

  // Unknown flags and environment_flags.cc-only aliases.
  EXPECT_EQ(RunController(&manager, {"--unknown_centipede_flag=1"}),
            kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"--stop_after=5s"}),
            kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"--first_shard_index=0"}),
            kFuzzTestControllerFailure);

  // Non-`--flag=val` forms are not supported.
  EXPECT_EQ(RunController(&manager, {"positional_arg"}),
            kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"--"}), kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"-"}), kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"--=1"}), kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"--exit_on_crash"}),
            kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"--noexit_on_crash"}),
            kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"--noexit_on_crash=true"}),
            kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"-num_runs=2"}),
            kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"--num_runs", "2"}),
            kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"--num_runs"}),
            kFuzzTestControllerFailure);

  // Malformed values.
  EXPECT_EQ(RunController(&manager, {"--num_runs=not_a_number"}),
            kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"--exit_on_crash=maybe"}),
            kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"--exit_on_crash="}),
            kFuzzTestControllerFailure);

  // Null views pointer with non-zero count.
  const FuzzTestBytesViews invalid_views = {/*views=*/nullptr, /*count=*/1};
  EXPECT_EQ(FuzzTestControllerRun(&manager, &invalid_views),
            kFuzzTestControllerFailure);

  // Invalid shard / batch invariants.
  EXPECT_EQ(RunController(&manager, {"--batch_size=0"}),
            kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"--total_shards=0"}),
            kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"--total_shards=1", "--num_threads=2"}),
            kFuzzTestControllerFailure);
  EXPECT_EQ(RunController(&manager, {"--total_shards=1", "--my_shard_index=1"}),
            kFuzzTestControllerFailure);

  EXPECT_EQ(state.adapters_constructed.load(), 0);
}

TEST(EngineControllerTest, InvokesCentipedeBinaryViaCommandWhenEnvVarIsSet) {
  const std::filesystem::path centipede_binary_path =
      GetDataDependencyFilepath("centipede/centipede_uninstrumented");
  const std::filesystem::path test_binary_path = GetDataDependencyFilepath(
      "centipede/testing/test_binary_for_engine_testing");
  ScopedEnvVar centipede_env("FUZZTEST_CENTIPEDE_BINARY_PATH",
                             centipede_binary_path.string());

  TempDir tmp_dir("engine_controller_env_var_centipede_bin");
  FakeAdapterState state;
  const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);

  // `--stop_after` and `--exit_on_crash` (without `=val`) are only accepted by
  // the standalone Centipede binary, confirming execution was delegated via
  // `Command` rather than parsed in-process.
  EXPECT_EQ(
      RunController(&manager,
                    {
                        absl::StrCat("--binary=", test_binary_path.string()),
                        absl::StrCat("--workdir=", tmp_dir.path().string()),
                        "--test_name=some_test",
                        "--populate_binary_info=false",
                        "--exit_on_crash",
                        "--stop_after=10s",
                    }),
      kFuzzTestControllerFailure);
  EXPECT_EQ(state.adapters_constructed.load(), 0);

  Environment expected_env;
  expected_env.workdir = tmp_dir.path().string();
  expected_env.coverage_binary = test_binary_path.string();
  expected_env.binary_name = test_binary_path.filename().string();
  expected_env.UpdateBinaryHashIfEmpty();
  const WorkDir wd{expected_env};
  const std::string crash_hash = Hash(ToByteArray("mutant_3"));
  const std::filesystem::path reproducer_path =
      std::filesystem::path(wd.CrashReproducerDirPaths().MyShard()) /
      crash_hash;
  ASSERT_TRUE(std::filesystem::exists(reproducer_path));
  std::string reproducer_content;
  ReadFromLocalFile(reproducer_path.string(), reproducer_content);
  EXPECT_EQ(reproducer_content, "mutant_3");
}

TEST(EngineControllerTest, ForwardsControllerFlagsToBinaryWhenEnvVarIsSet) {
  TempDir tmp_dir("engine_controller_env_var_forwarding");
  const std::filesystem::path args_out_path = tmp_dir.path() / "args.txt";
  const std::filesystem::path script_path =
      tmp_dir.path() / "fake_centipede.sh";

  WriteToLocalFile(script_path.string(),
                   absl::StrCat("#!/bin/sh\n"
                                ": > '",
                                args_out_path.string(),
                                "'\n"
                                "for arg in \"$@\"; do\n"
                                "  printf '%s\\n' \"$arg\" >> '",
                                args_out_path.string(),
                                "'\n"
                                "done\n"
                                "exit 0\n"));
  std::filesystem::permissions(script_path, std::filesystem::perms::owner_all);

  ScopedEnvVar centipede_env("FUZZTEST_CENTIPEDE_BINARY_PATH",
                             script_path.string());
  FakeAdapterState state;
  const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);

  EXPECT_EQ(RunController(&manager,
                          {
                              "--binary=/path/with spaces/target 'test_name' "
                              "--exact --nocapture @@",
                              "--workdir=/tmp/dir with 'quotes'",
                              "--exit_on_crash",
                          }),
            kFuzzTestControllerSuccess);
  EXPECT_EQ(state.adapters_constructed.load(), 0);

  std::string recorded_output;
  ReadFromLocalFile(args_out_path.string(), recorded_output);
  const std::vector<std::string> recorded_args =
      absl::StrSplit(recorded_output, '\n', absl::SkipEmpty());
  EXPECT_THAT(recorded_args, ElementsAre("--binary=/path/with spaces/target "
                                         "'test_name' --exact --nocapture @@",
                                         "--workdir=/tmp/dir with 'quotes'",
                                         "--exit_on_crash"));

  // Null flags pointer is treated as zero extra arguments.
  EXPECT_EQ(FuzzTestControllerRun(&manager, /*flags=*/nullptr),
            kFuzzTestControllerSuccess);
  recorded_output.clear();
  ReadFromLocalFile(args_out_path.string(), recorded_output);
  EXPECT_THAT(recorded_output, IsEmpty());
}

TEST(EngineControllerTest, FailsWhenEnvVarBinaryExitsNonZeroOrIsInvalid) {
  TempDir tmp_dir("engine_controller_env_var_failures");
  FakeAdapterState state;
  const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);

  // Non-zero exit status from binary.
  {
    const std::filesystem::path failing_script = tmp_dir.path() / "fail.sh";
    WriteToLocalFile(failing_script.string(), "#!/bin/sh\nexit 7\n");
    std::filesystem::permissions(failing_script,
                                 std::filesystem::perms::owner_all);
    ScopedEnvVar centipede_env("FUZZTEST_CENTIPEDE_BINARY_PATH",
                               failing_script.string());
    EXPECT_EQ(RunController(&manager, {"--num_runs=1"}),
              kFuzzTestControllerFailure);

    const FuzzTestBytesViews invalid_views = {/*views=*/nullptr, /*count=*/1};
    EXPECT_EQ(FuzzTestControllerRun(&manager, &invalid_views),
              kFuzzTestControllerFailure);
  }

  // Non-existent binary path.
  {
    ScopedEnvVar centipede_env("FUZZTEST_CENTIPEDE_BINARY_PATH",
                               (tmp_dir.path() / "does_not_exist").string());
    EXPECT_EQ(RunController(&manager, {}), kFuzzTestControllerFailure);
  }

  // Empty FUZZTEST_CENTIPEDE_BINARY_PATH value.
  {
    ScopedEnvVar centipede_env("FUZZTEST_CENTIPEDE_BINARY_PATH", "");
    EXPECT_EQ(RunController(&manager, {}), kFuzzTestControllerFailure);
  }

  EXPECT_EQ(state.adapters_constructed.load(), 0);
}

}  // namespace
}  // namespace fuzztest::internal
