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

#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "absl/strings/str_cat.h"
#include "./centipede/engine_abi.h"
#include "./centipede/engine_controller_abi.h"
#include "./centipede/engine_worker_abi.h"

namespace {

FuzzTestBytesView ToBytesView(std::string_view sv) {
  return {reinterpret_cast<const uint8_t*>(sv.data()), sv.size()};
}

void SetUpCoverageDomains(FuzzTestAdapterCtx* ctx,
                          const FuzzTestCoverageDomainRegistry* registry) {
  static constexpr std::string_view kDomainName = "base";
  const FuzzTestCoverageDomain domain = {
      /*domain_id=*/0,
      /*name=*/ToBytesView(kDomainName),
      /*feature_id_bit_size=*/27,
      /*counter_bit_size=*/0,
  };
  registry->Register(registry->ctx, &domain);
}

struct AdapterCtx {
  const FuzzTestDiagnosticSink* diagnostic_sink;
};

struct TestInput {
  std::string content;
};

void EmitInput(std::string_view input_content, const FuzzTestInputSink* sink) {
  sink->Emit(sink->ctx, reinterpret_cast<FuzzTestInputHandle>(
                            new TestInput{std::string{input_content}}));
}

void GetRandomSeedInput(FuzzTestAdapterCtx* ctx,
                        const FuzzTestInputSink* sink) {
  EmitInput("random_seed", sink);
}

void Mutate(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input, int shrink,
            const FuzzTestInputSink* sink) {
  const auto* input_object = reinterpret_cast<TestInput*>(input);
  if (input_object->content == "random_seed") {
    EmitInput("mutant_1", sink);
  } else if (input_object->content == "mutant_1") {
    EmitInput("mutant_2", sink);
  } else if (input_object->content == "mutant_2") {
    EmitInput("mutant_3", sink);
  } else {
    EmitInput("bad_input", sink);
  }
}

void AddFeature(uint32_t domain, uint32_t feature, uint32_t counter,
                std::vector<uint64_t>& out) {
  out.push_back((static_cast<uint64_t>(domain) << 59) |
                (static_cast<uint64_t>(feature) << 32) | counter);
}

void Execute(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input,
             const FuzzTestFeedbackSink* sink) {
  std::vector<uint64_t> features;
  auto* adapter_ctx = reinterpret_cast<AdapterCtx*>(ctx);
  const auto* input_object = reinterpret_cast<TestInput*>(input);
  if (input_object->content == "random_seed") {
    AddFeature(0, 0, 0, features);
    AddFeature(0, 1, 0, features);
    AddFeature(0, 2, 0, features);
  } else if (input_object->content == "mutant_1") {
    AddFeature(0, 3, 0, features);
    AddFeature(0, 4, 0, features);
  } else if (input_object->content == "mutant_2") {
    AddFeature(0, 5, 0, features);
  } else if (input_object->content == "mutant_3") {
    static constexpr std::string_view kDescription = "some_failure_description";
    static constexpr std::string_view kSignature = "some_signature";
    const auto description_view = ToBytesView(kDescription);
    const auto signature_view = ToBytesView(kSignature);
    adapter_ctx->diagnostic_sink->EmitFinding(
        adapter_ctx->diagnostic_sink->ctx, &description_view, &signature_view);
  } else {
    static constexpr std::string_view kDescription =
        "some_other_failure_description";
    static constexpr std::string_view kSignature = "some_other_signature";
    const auto description_view = ToBytesView(kDescription);
    const auto signature_view = ToBytesView(kSignature);
    adapter_ctx->diagnostic_sink->EmitFinding(
        adapter_ctx->diagnostic_sink->ctx, &description_view, &signature_view);
  }
  const auto features_view = FuzzTestUint64sView{
      features.data(),
      features.size(),
  };
  sink->EmitCoverageFeatures(sink->ctx, &features_view);
}

void DeserializeInputContent(FuzzTestAdapterCtx* ctx,
                             const FuzzTestBytesView* content,
                             const FuzzTestInputSink* sink) {
  auto* input = new TestInput{
      std::string{reinterpret_cast<const char*>(content->data), content->size}};
  sink->Emit(sink->ctx, reinterpret_cast<FuzzTestInputHandle>(input));
}

void SerializeInputContent(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input,
                           const FuzzTestBytesSink* sink) {
  auto* input_object = reinterpret_cast<TestInput*>(input);
  const FuzzTestBytesView bytes = {
      /*data=*/reinterpret_cast<const uint8_t*>(input_object->content.data()),
      /*size=*/input_object->content.size(),
  };
  sink->Emit(sink->ctx, &bytes);
}

void FreeInput(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input) {
  delete reinterpret_cast<TestInput*>(input);
}

void FreeCtx(FuzzTestAdapterCtx* ctx) {
  delete reinterpret_cast<AdapterCtx*>(ctx);
}

void ConstructAdapter(const FuzzTestDiagnosticSink* sink,
                      FuzzTestAdapter* adapter_out) {
  adapter_out->ctx =
      reinterpret_cast<FuzzTestAdapterCtx*>(new AdapterCtx{sink});
  adapter_out->SetUpCoverageDomains = SetUpCoverageDomains;
  adapter_out->GetRandomSeedInput = GetRandomSeedInput;
  adapter_out->Mutate = Mutate;
  adapter_out->Execute = Execute;
  adapter_out->DeserializeInputContent = DeserializeInputContent;
  adapter_out->SerializeInputContent = SerializeInputContent;
  adapter_out->FreeInput = FreeInput;
  adapter_out->FreeCtx = FreeCtx;
}

FuzzTestControllerStatus ControllerRun(const FuzzTestAdapterManager* manager,
                                       const std::vector<std::string>& flags) {
  std::vector<FuzzTestBytesView> flags_bytes_view_list;
  flags_bytes_view_list.reserve(flags.size());
  for (const auto& flag : flags) {
    flags_bytes_view_list.push_back(FuzzTestBytesView{
        /*data=*/reinterpret_cast<const uint8_t*>(flag.data()),
        /*size=*/flag.size(),
    });
  }
  const FuzzTestBytesViews flags_bytes_views = {
      /*views=*/flags_bytes_view_list.data(),
      /*count=*/flags_bytes_view_list.size(),
  };
  return FuzzTestControllerRun(manager, &flags_bytes_views);
}

}  // namespace

int main(int argc, char** argv) {
  FuzzTestAdapterManager manager = {
      /*ctx=*/nullptr,
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
        ConstructAdapter(diagnostic_sink, adapter_out);
      },
  };
  if (const auto worker_status = FuzzTestWorkerMaybeRun(&manager);
      worker_status != kFuzzTestWorkerNotRequired) {
    return worker_status == kFuzzTestWorkerSuccess ? EXIT_SUCCESS
                                                   : EXIT_FAILURE;
  }
  return ControllerRun(&manager,
                       {absl::StrCat("--binary=", argv[0]),
                        "--test_name=some_test", "--populate_binary_info=0",
                        "--fork_server=0", "--exit_on_crash"}) ==
                 kFuzzTestControllerSuccess
             ? EXIT_SUCCESS
             : EXIT_FAILURE;
}
