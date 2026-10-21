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

#include "./centipede/in_process_centipede_callbacks.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./centipede/centipede_interface.h"
#include "./centipede/engine_abi.h"
#include "./centipede/environment.h"
#include "./centipede/execution_metadata.h"
#include "./centipede/feature.h"
#include "./centipede/mutation_data.h"
#include "./centipede/runner_interface.h"
#include "./centipede/runner_result.h"
#include "./centipede/stop.h"
#include "./centipede/thread_pool.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"
#include "./common/defs.h"
#include "./common/hash.h"
#include "./common/temp_dir.h"

namespace fuzztest::internal {
namespace {

using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::SizeIs;
using ::testing::StartsWith;

FuzzTestBytesView ToBytesView(std::string_view sv) {
  return {reinterpret_cast<const uint8_t*>(sv.data()), sv.size()};
}

ByteArray ToByteArray(std::string_view sv) {
  return ByteArray(sv.begin(), sv.end());
}

std::string ToString(ByteSpan span) {
  return std::string(reinterpret_cast<const char*>(span.data()), span.size());
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
  std::string metadata;
};

struct FakeAdapterState {
  const FuzzTestDiagnosticSink* diagnostic_sink = nullptr;
  int active_inputs = 0;
  int active_adapters = 0;
  int random_seed_counter = 0;
  std::vector<std::string> preset_seeds;
};

void EmitFakeInput(FakeAdapterState* state, std::string content,
                   const FuzzTestInputSink* sink) {
  ++state->active_inputs;
  sink->Emit(sink->ctx, reinterpret_cast<FuzzTestInputHandle>(
                            new FakeInput{std::move(content), ""}));
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

  static constexpr std::string_view kCounterDomainName = "counter";
  const FuzzTestCoverageDomain counter_domain = {
      /*domain_id=*/1,
      /*name=*/ToBytesView(kCounterDomainName),
      /*feature_id_bit_size=*/20,
      /*counter_bit_size=*/8,
  };
  registry->Register(registry->ctx, &counter_domain);
}

void FakeGetPresetSeedInputs(FuzzTestAdapterCtx* ctx,
                             const FuzzTestInputSink* sink) {
  auto* state = reinterpret_cast<FakeAdapterState*>(ctx);
  for (const std::string& seed : state->preset_seeds) {
    EmitFakeInput(state, seed, sink);
  }
}

void FakeGetRandomSeedInput(FuzzTestAdapterCtx* ctx,
                            const FuzzTestInputSink* sink) {
  auto* state = reinterpret_cast<FakeAdapterState*>(ctx);
  if (state->preset_seeds.empty()) {
    EmitFakeInput(state, "random_seed", sink);
    return;
  }
  EmitFakeInput(
      state, absl::StrCat("random_seed_", state->random_seed_counter++), sink);
}

void FakeMutate(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input, int shrink,
                const FuzzTestInputSink* sink) {
  auto* state = reinterpret_cast<FakeAdapterState*>(ctx);
  const auto* input_obj = reinterpret_cast<FakeInput*>(input);
  if (input_obj->content == "random_seed") {
    EmitFakeInput(state, "mutant_1", sink);
  } else if (input_obj->content == "mutant_1") {
    EmitFakeInput(state, "mutant_2", sink);
  } else if (input_obj->content == "mutant_2") {
    EmitFakeInput(state, "mutant_3", sink);
  } else if (!input_obj->metadata.empty()) {
    EmitFakeInput(
        state, absl::StrCat(input_obj->content, "_meta:", input_obj->metadata),
        sink);
  } else {
    EmitFakeInput(state, absl::StrCat(input_obj->content, "_mutated"), sink);
  }
}

void FakeCrossOver(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle origin,
                   FuzzTestInputHandle other, const FuzzTestInputSink* sink) {
  auto* state = reinterpret_cast<FakeAdapterState*>(ctx);
  const auto* origin_obj = reinterpret_cast<FakeInput*>(origin);
  const auto* other_obj = reinterpret_cast<FakeInput*>(other);
  EmitFakeInput(
      state, absl::StrCat(origin_obj->content, "+", other_obj->content), sink);
}

void FakeExecute(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input,
                 const FuzzTestFeedbackSink* sink) {
  auto* state = reinterpret_cast<FakeAdapterState*>(ctx);
  auto* input_obj = reinterpret_cast<FakeInput*>(input);
  std::vector<uint64_t> features;

  if (input_obj->content == "random_seed") {
    features.push_back(MakeEngineFeature(0, 0, 0));
    features.push_back(MakeEngineFeature(0, 1, 0));
    features.push_back(MakeEngineFeature(0, 2, 0));
  } else if (input_obj->content == "mutant_1") {
    features.push_back(MakeEngineFeature(0, 3, 0));
    features.push_back(MakeEngineFeature(0, 4, 0));
  } else if (input_obj->content == "mutant_2") {
    features.push_back(MakeEngineFeature(0, 5, 0));
  } else if (input_obj->content == "mutant_3") {
    static constexpr std::string_view kDescription = "some_failure_description";
    static constexpr std::string_view kSignature = "some_signature";
    const auto description_view = ToBytesView(kDescription);
    const auto signature_view = ToBytesView(kSignature);
    state->diagnostic_sink->EmitFinding(state->diagnostic_sink->ctx,
                                        &description_view, &signature_view);
  } else if (input_obj->content == "empty_signature_finding_input") {
    static constexpr std::string_view kDescription = "empty_sig_description";
    const auto description_view = ToBytesView(kDescription);
    const auto signature_view = ToBytesView("");
    state->diagnostic_sink->EmitFinding(state->diagnostic_sink->ctx,
                                        &description_view, &signature_view);
  } else if (input_obj->content == "long_finding_input") {
    const std::string long_description(5000, 'd');
    const std::string long_signature(5000, 's');
    const auto description_view = ToBytesView(long_description);
    const auto signature_view = ToBytesView(long_signature);
    state->diagnostic_sink->EmitFinding(state->diagnostic_sink->ctx,
                                        &description_view, &signature_view);
  } else if (input_obj->content == "concurrent_findings_input") {
    ThreadPool threads(2);
    threads.Schedule([state] {
      static constexpr std::string_view kDesc1 = "concurrent_finding_1";
      static constexpr std::string_view kSig1 = "concurrent_sig_1";
      const auto desc_view = ToBytesView(kDesc1);
      const auto sig_view = ToBytesView(kSig1);
      state->diagnostic_sink->EmitFinding(state->diagnostic_sink->ctx,
                                          &desc_view, &sig_view);
    });
    threads.Schedule([state] {
      static constexpr std::string_view kDesc2 = "concurrent_finding_2";
      static constexpr std::string_view kSig2 = "concurrent_sig_2";
      const auto desc_view = ToBytesView(kDesc2);
      const auto sig_view = ToBytesView(kSig2);
      state->diagnostic_sink->EmitFinding(state->diagnostic_sink->ctx,
                                          &desc_view, &sig_view);
    });
  } else if (input_obj->content == "setup_error_input") {
    static constexpr std::string_view kError = "some_setup_error";
    const auto error_view = ToBytesView(kError);
    state->diagnostic_sink->EmitError(state->diagnostic_sink->ctx, &error_view);
  } else if (input_obj->content == "bad_prefix_finding_input") {
    static constexpr std::string_view kBadDesc = "SETUP FAILURE: bad finding";
    static constexpr std::string_view kSig = "sig";
    const auto desc_view = ToBytesView(kBadDesc);
    const auto sig_view = ToBytesView(kSig);
    state->diagnostic_sink->EmitFinding(state->diagnostic_sink->ctx, &desc_view,
                                        &sig_view);
  } else if (input_obj->content == "with_counter_and_meta") {
    features.push_back(MakeEngineFeature(0, 7, 0));
    // Counter domain 1 has 8-bit counter; top 6 bits of 0b101100'00 (0xB0)
    // = 44.
    features.push_back(MakeEngineFeature(1, 10, 0xB0));
    input_obj->metadata = "recorded_cmp_meta";
  }

  const FuzzTestUint64sView features_view{features.data(), features.size()};
  sink->EmitCoverageFeatures(sink->ctx, &features_view);
}

void FakeDeserializeInputContent(FuzzTestAdapterCtx* ctx,
                                 const FuzzTestBytesView* content,
                                 const FuzzTestInputSink* sink) {
  auto* state = reinterpret_cast<FakeAdapterState*>(ctx);
  EmitFakeInput(
      state,
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

void FakeSerializeInputMetadata(FuzzTestAdapterCtx* ctx,
                                FuzzTestInputHandle input,
                                const FuzzTestBytesSink* sink) {
  const auto* input_obj = reinterpret_cast<FakeInput*>(input);
  const FuzzTestBytesView bytes = ToBytesView(input_obj->metadata);
  sink->Emit(sink->ctx, &bytes);
}

void FakeUpdateInputMetadata(FuzzTestAdapterCtx* ctx,
                             const FuzzTestBytesView* metadata,
                             FuzzTestInputHandle input) {
  auto* input_obj = reinterpret_cast<FakeInput*>(input);
  input_obj->metadata.assign(reinterpret_cast<const char*>(metadata->data),
                             metadata->size);
}

void FakeFreeInput(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input) {
  auto* state = reinterpret_cast<FakeAdapterState*>(ctx);
  --state->active_inputs;
  delete reinterpret_cast<FakeInput*>(input);
}

void FakeFreeCtx(FuzzTestAdapterCtx* ctx) {
  auto* state = reinterpret_cast<FakeAdapterState*>(ctx);
  --state->active_adapters;
}

FuzzTestAdapterManager MakeFakeAdapterManager(FakeAdapterState* state,
                                              bool enable_crossover = false) {
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
      enable_crossover
          ? +[](FuzzTestAdapterManagerCtx* ctx,
                const FuzzTestDiagnosticSink* diagnostic_sink,
                FuzzTestAdapter* adapter_out) {
              auto* state = reinterpret_cast<FakeAdapterState*>(ctx);
              state->diagnostic_sink = diagnostic_sink;
              ++state->active_adapters;
              adapter_out->ctx = reinterpret_cast<FuzzTestAdapterCtx*>(state);
              adapter_out->SetUpCoverageDomains = FakeSetUpCoverageDomains;
              adapter_out->GetPresetSeedInputs = FakeGetPresetSeedInputs;
              adapter_out->GetRandomSeedInput = FakeGetRandomSeedInput;
              adapter_out->Mutate = FakeMutate;
              adapter_out->CrossOver = FakeCrossOver;
              adapter_out->Execute = FakeExecute;
              adapter_out->DeserializeInputContent =
                  FakeDeserializeInputContent;
              adapter_out->SerializeInputContent = FakeSerializeInputContent;
              adapter_out->SerializeInputMetadata = FakeSerializeInputMetadata;
              adapter_out->UpdateInputMetadata = FakeUpdateInputMetadata;
              adapter_out->FreeInput = FakeFreeInput;
              adapter_out->FreeCtx = FakeFreeCtx;
            }
          : +[](FuzzTestAdapterManagerCtx* ctx,
                const FuzzTestDiagnosticSink* diagnostic_sink,
                FuzzTestAdapter* adapter_out) {
              auto* state = reinterpret_cast<FakeAdapterState*>(ctx);
              state->diagnostic_sink = diagnostic_sink;
              ++state->active_adapters;
              adapter_out->ctx = reinterpret_cast<FuzzTestAdapterCtx*>(state);
              adapter_out->SetUpCoverageDomains = FakeSetUpCoverageDomains;
              adapter_out->GetPresetSeedInputs = FakeGetPresetSeedInputs;
              adapter_out->GetRandomSeedInput = FakeGetRandomSeedInput;
              adapter_out->Mutate = FakeMutate;
              adapter_out->CrossOver = nullptr;
              adapter_out->Execute = FakeExecute;
              adapter_out->DeserializeInputContent =
                  FakeDeserializeInputContent;
              adapter_out->SerializeInputContent = FakeSerializeInputContent;
              adapter_out->SerializeInputMetadata = FakeSerializeInputMetadata;
              adapter_out->UpdateInputMetadata = FakeUpdateInputMetadata;
              adapter_out->FreeInput = FakeFreeInput;
              adapter_out->FreeCtx = FakeFreeCtx;
            },
  };
}

TEST(InProcessCentipedeCallbacksTest, GetSeedsReturnsPresetAndRandomSeeds) {
  FakeAdapterState state;
  state.preset_seeds = {"preset_0", "preset_1"};
  const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);

  Environment env;
  env.test_name = "some_test";
  StopCondition stop_condition;
  {
    InProcessCentipedeCallbacks callbacks(env, stop_condition, &manager);
    EXPECT_EQ(state.active_adapters, 1);

    std::vector<ByteArray> seeds;
    const size_t total_available = callbacks.GetSeeds(/*num_seeds=*/5, seeds);
    EXPECT_EQ(total_available, 32);
    ASSERT_THAT(seeds, SizeIs(5));
    EXPECT_EQ(ToString(seeds[0]), "preset_0");
    EXPECT_EQ(ToString(seeds[1]), "preset_1");
    EXPECT_EQ(ToString(seeds[2]), "random_seed_0");
    EXPECT_EQ(ToString(seeds[3]), "random_seed_1");
    EXPECT_EQ(ToString(seeds[4]), "random_seed_2");
    EXPECT_EQ(state.active_inputs, 0);
  }
  EXPECT_EQ(state.active_adapters, 0);
}

TEST(InProcessCentipedeCallbacksTest, MutateUsesMetadataAndCrossOver) {
  FakeAdapterState state;
  const FuzzTestAdapterManager manager =
      MakeFakeAdapterManager(&state, /*enable_crossover=*/true);
  const ByteArray input_bytes = ToByteArray("input_a");
  ExecutionMetadata metadata;
  metadata.cmp_data = ToByteArray("cmp_payload");
  const std::vector<MutationInputRef> mutation_inputs = {
      MutationInputRef{input_bytes, &metadata},
  };
  StopCondition stop_condition;

  {
    Environment env;
    env.crossover_level = 0;
    InProcessCentipedeCallbacks callbacks(env, stop_condition, &manager);

    const std::vector<Mutant> mutants =
        callbacks.Mutate(mutation_inputs, /*num_mutants=*/2);
    ASSERT_THAT(mutants, SizeIs(2));
    EXPECT_EQ(ToString(mutants[0].data), "input_a_meta:cmp_payload");
    EXPECT_EQ(mutants[0].origin, 0);
    EXPECT_EQ(ToString(mutants[1].data), "input_a_meta:cmp_payload");
    EXPECT_EQ(mutants[1].origin, 0);
    EXPECT_EQ(state.active_inputs, 0);
  }

  {
    Environment crossover_env;
    crossover_env.crossover_level = 100;
    InProcessCentipedeCallbacks crossover_callbacks(crossover_env,
                                                    stop_condition, &manager);
    const std::vector<Mutant> crossover_mutants =
        crossover_callbacks.Mutate(mutation_inputs, /*num_mutants=*/1);
    ASSERT_THAT(crossover_mutants, SizeIs(1));
    EXPECT_EQ(ToString(crossover_mutants[0].data), "input_a+input_a");
    EXPECT_EQ(crossover_mutants[0].origin, 0);
    EXPECT_EQ(state.active_inputs, 0);
  }
}

TEST(InProcessCentipedeCallbacksTest,
     ExecuteConvertsFeaturesAndSerializesMetadata) {
  FakeAdapterState state;
  const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);

  Environment env;
  StopCondition stop_condition;
  InProcessCentipedeCallbacks callbacks(env, stop_condition, &manager);

  const ByteArray input_0 = ToByteArray("random_seed");
  const ByteArray input_1 = ToByteArray("with_counter_and_meta");
  const std::vector<ByteSpan> batch = {input_0, input_1};

  BatchResult batch_result;
  EXPECT_TRUE(callbacks.Execute("binary", batch, batch_result));
  EXPECT_EQ(batch_result.exit_code(), EXIT_SUCCESS);
  EXPECT_EQ(batch_result.num_outputs_read(), 2);
  ASSERT_THAT(batch_result.results(), SizeIs(2));

  EXPECT_THAT(batch_result.results()[0].features(),
              ElementsAre(feature_domains::Domain{0}.ConvertToMe(0),
                          feature_domains::Domain{0}.ConvertToMe(1),
                          feature_domains::Domain{0}.ConvertToMe(2)));
  EXPECT_THAT(batch_result.results()[0].metadata().cmp_data, IsEmpty());

  const uint64_t expected_counter_feature_id = (10ULL << 6) | (0xB0 >> 2);
  EXPECT_THAT(batch_result.results()[1].features(),
              ElementsAre(feature_domains::Domain{0}.ConvertToMe(7),
                          feature_domains::Domain{1}.ConvertToMe(
                              expected_counter_feature_id)));
  EXPECT_EQ(ToString(batch_result.results()[1].metadata().cmp_data),
            "recorded_cmp_meta");
  EXPECT_EQ(state.active_inputs, 0);
}

TEST(InProcessCentipedeCallbacksTest,
     ExecuteReportsFindingAndResetsOnNextBatch) {
  FakeAdapterState state;
  const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);

  Environment env;
  StopCondition stop_condition;
  InProcessCentipedeCallbacks callbacks(env, stop_condition, &manager);

  const ByteArray input_0 = ToByteArray("random_seed");
  const ByteArray input_1 = ToByteArray("mutant_3");
  const ByteArray input_2 = ToByteArray("mutant_1");
  const std::vector<ByteSpan> batch = {input_0, input_1, input_2};

  BatchResult batch_result;
  EXPECT_FALSE(callbacks.Execute("binary", batch, batch_result));
  EXPECT_EQ(batch_result.exit_code(), EXIT_FAILURE);
  EXPECT_TRUE(batch_result.IsInputFailure());
  EXPECT_EQ(batch_result.num_outputs_read(), 1);
  EXPECT_EQ(batch_result.failure_description(), "some_failure_description");
  EXPECT_EQ(batch_result.failure_signature(), Hash("some_signature"));
  EXPECT_EQ(state.active_inputs, 0);

  // Subsequent batch without findings should succeed cleanly.
  EXPECT_TRUE(callbacks.Execute("binary", {input_0}, batch_result));
  EXPECT_EQ(batch_result.exit_code(), EXIT_SUCCESS);
  EXPECT_EQ(batch_result.num_outputs_read(), 1);
  EXPECT_THAT(batch_result.failure_description(), IsEmpty());
  EXPECT_THAT(batch_result.failure_signature(), IsEmpty());
}

TEST(InProcessCentipedeCallbacksTest,
     ExecuteCapsLongFailureAndFallsBackOnEmptySignature) {
  FakeAdapterState state;
  const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);

  Environment env;
  StopCondition stop_condition;
  InProcessCentipedeCallbacks callbacks(env, stop_condition, &manager);

  BatchResult batch_result;
  const ByteArray empty_sig_input =
      ToByteArray("empty_signature_finding_input");
  EXPECT_FALSE(callbacks.Execute("binary", {empty_sig_input}, batch_result));
  EXPECT_EQ(batch_result.failure_description(), "empty_sig_description");
  EXPECT_EQ(batch_result.failure_signature(), Hash("empty_sig_description"));

  const ByteArray long_finding_input = ToByteArray("long_finding_input");
  EXPECT_FALSE(callbacks.Execute("binary", {long_finding_input}, batch_result));
  const std::string expected_full_description(5000, 'd');
  EXPECT_GE(batch_result.failure_description().size(), 100);
  EXPECT_LT(batch_result.failure_description().size(),
            expected_full_description.size());
  EXPECT_THAT(expected_full_description,
              StartsWith(batch_result.failure_description()));
  EXPECT_EQ(batch_result.failure_signature(),
            Hash(std::string(batch_result.failure_description().size(), 's')));
}

TEST(InProcessCentipedeCallbacksTest,
     ExecuteHandlesConcurrentFindingsAndErrors) {
  Environment env;
  StopCondition stop_condition;
  BatchResult batch_result;

  {
    FakeAdapterState state;
    const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);
    InProcessCentipedeCallbacks callbacks(env, stop_condition, &manager);
    const ByteArray concurrent_input = ToByteArray("concurrent_findings_input");

    for (int i = 0; i < 20; ++i) {
      EXPECT_FALSE(
          callbacks.Execute("binary", {concurrent_input}, batch_result));
      if (batch_result.failure_description() == "concurrent_finding_1") {
        EXPECT_EQ(batch_result.failure_signature(), Hash("concurrent_sig_1"));
      } else {
        EXPECT_EQ(batch_result.failure_description(), "concurrent_finding_2");
        EXPECT_EQ(batch_result.failure_signature(), Hash("concurrent_sig_2"));
      }
    }
  }

  for (int i = 0; i < 20; ++i) {
    stop_condition.ClearStopRequest();
    FakeAdapterState state;
    const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);
    InProcessCentipedeCallbacks callbacks(env, stop_condition, &manager);
    const ByteArray ok_input = ToByteArray("random_seed");

    {
      ThreadPool error_emitter(1);
      error_emitter.Schedule([&state] {
        static constexpr std::string_view kError = "concurrent_setup_error";
        const auto error_view = ToBytesView(kError);
        state.diagnostic_sink->EmitError(state.diagnostic_sink->ctx,
                                         &error_view);
      });
      while (callbacks.Execute("binary", {ok_input}, batch_result) &&
             !stop_condition.StopRequested()) {
      }
    }
    if (stop_condition.StopRequested()) {
      EXPECT_FALSE(callbacks.Execute("binary", {ok_input}, batch_result));
    }
    EXPECT_EQ(batch_result.failure_description(),
              "SETUP FAILURE: concurrent_setup_error");
    EXPECT_EQ(batch_result.failure_signature(),
              Hash("SETUP FAILURE: concurrent_setup_error"));
    StopCondition::StopRequest stop_request;
    ASSERT_TRUE(stop_condition.StopRequested(&stop_request));
    EXPECT_EQ(stop_request.reason, "SETUP FAILURE: concurrent_setup_error");
  }
}

TEST(InProcessCentipedeCallbacksTest, ExecuteReportsSetupErrors) {
  Environment env;
  StopCondition stop_condition;
  BatchResult batch_result;

  {
    FakeAdapterState state;
    const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);
    InProcessCentipedeCallbacks callbacks(env, stop_condition, &manager);

    const ByteArray setup_error_input = ToByteArray("setup_error_input");
    EXPECT_FALSE(
        callbacks.Execute("binary", {setup_error_input}, batch_result));
    EXPECT_EQ(batch_result.exit_code(), EXIT_FAILURE);
    EXPECT_TRUE(batch_result.IsSetupFailure());
    EXPECT_EQ(batch_result.failure_description(),
              "SETUP FAILURE: some_setup_error");
    EXPECT_EQ(state.active_inputs, 0);
  }

  EXPECT_TRUE(stop_condition.StopRequested());
  stop_condition.ClearStopRequest();

  {
    // Bad finding prefix should also be reported as a setup failure.
    FakeAdapterState state_bad_prefix;
    const FuzzTestAdapterManager manager_bad_prefix =
        MakeFakeAdapterManager(&state_bad_prefix);
    InProcessCentipedeCallbacks callbacks_bad_prefix(env, stop_condition,
                                                     &manager_bad_prefix);
    const ByteArray bad_prefix_input = ToByteArray("bad_prefix_finding_input");
    EXPECT_FALSE(callbacks_bad_prefix.Execute("binary", {bad_prefix_input},
                                              batch_result));
    EXPECT_TRUE(batch_result.IsSetupFailure());
    EXPECT_EQ(batch_result.failure_description(),
              "SETUP FAILURE: Bad prefix in the finding description");
  }
}

TEST(InProcessCentipedeCallbacksTest,
     CentipedeMainFindsCrashWithInProcessCallbacks) {
  TempDir tmp_dir("in_process_callbacks_test");
  FakeAdapterState state;
  const FuzzTestAdapterManager manager = MakeFakeAdapterManager(&state);

  Environment env;
  env.workdir = tmp_dir.path();
  env.test_name = "some_test";
  env.populate_binary_info = false;
  env.exit_on_crash = true;
  env.stop_at = absl::Now() + absl::Seconds(10);

  InProcessCentipedeCallbacksFactory factory(&manager);
  StopCondition stop_condition;
  EXPECT_EQ(CentipedeMain(env, factory, &stop_condition), EXIT_FAILURE);

  const WorkDir wd{env};
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

TEST(InProcessCentipedeCallbacksTest,
     WorksWithCreateFuzzTestAdapterManagerFromRunnerCallbacks) {
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
