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

// A test binary for testing how the engine worker handles diagnostics (errors
// and findings) emitted by the test adapter. The content of each input selects
// the diagnostics to emit when executing and freeing the input.

#include <chrono>  // NOLINT: for polling in a background thread.
#include <cstdint>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <fstream>
#include <string>
#include <string_view>
#include <thread>  // NOLINT: for emitting diagnostics concurrently.

#include "./centipede/engine_abi.h"
#include "./centipede/engine_worker_abi.h"

namespace {

// The number of `Execute()` calls in the current process.
int num_executes = 0;

// The prefix of the input content for emitting a finding in `Execute()`, and
// then emitting an error from a background thread once the file at the path
// following the prefix exists. After emitting the error, the thread creates
// another file at the same path with `kErrorEmittedFileSuffix` appended.
constexpr std::string_view kFindingThenErrorOnFilePrefix =
    "finding_then_error_on_file:";
constexpr std::string_view kErrorEmittedFileSuffix = ".error_emitted";

struct AdapterCtx {
  const FuzzTestDiagnosticSink* diagnostic_sink;
};

struct TestInput {
  std::string content;
};

FuzzTestBytesView ToBytesView(std::string_view sv) {
  return {reinterpret_cast<const uint8_t*>(sv.data()), sv.size()};
}

void EmitError(const FuzzTestDiagnosticSink* sink, std::string_view message) {
  const auto message_view = ToBytesView(message);
  sink->EmitError(sink->ctx, &message_view);
}

void EmitFinding(const FuzzTestDiagnosticSink* sink,
                 std::string_view description, std::string_view signature) {
  const auto description_view = ToBytesView(description);
  const auto signature_view = ToBytesView(signature);
  sink->EmitFinding(sink->ctx, &description_view, &signature_view);
}

void EmitInput(std::string_view content, const FuzzTestInputSink* sink) {
  sink->Emit(sink->ctx, reinterpret_cast<FuzzTestInputHandle>(
                            new TestInput{std::string{content}}));
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

void GetRandomSeedInput(FuzzTestAdapterCtx* ctx,
                        const FuzzTestInputSink* sink) {
  EmitInput("ok", sink);
}

void Mutate(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input, int shrink,
            const FuzzTestInputSink* sink) {
  EmitInput("ok", sink);
}

void Execute(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input,
             const FuzzTestFeedbackSink* sink) {
  auto* adapter_ctx = reinterpret_cast<AdapterCtx*>(ctx);
  const FuzzTestDiagnosticSink* diagnostic_sink = adapter_ctx->diagnostic_sink;
  const std::string& content = reinterpret_cast<TestInput*>(input)->content;
  const bool is_first_execute = num_executes == 0;
  ++num_executes;

  if (content == "finding_then_error_on_free") {
    EmitFinding(diagnostic_sink, "finding_description", "finding_signature");
  } else if (content == "finding_on_first_execute") {
    if (is_first_execute) {
      EmitFinding(diagnostic_sink, "first_execute_description",
                  "first_execute_signature");
    }
  } else if (content == "error") {
    EmitError(diagnostic_sink, "error_in_execute");
  } else if (content == "error_then_finding") {
    EmitError(diagnostic_sink, "error_in_execute");
    EmitFinding(diagnostic_sink, "finding_description", "finding_signature");
  } else if (content == "finding_then_error") {
    EmitFinding(diagnostic_sink, "finding_description", "finding_signature");
    EmitError(diagnostic_sink, "error_in_execute");
  } else if (content == "racing_error_and_finding") {
    std::thread error_thread(
        [diagnostic_sink] { EmitError(diagnostic_sink, "error_in_execute"); });
    std::thread finding_thread([diagnostic_sink] {
      EmitFinding(diagnostic_sink, "finding_description", "finding_signature");
    });
    error_thread.join();
    finding_thread.join();
  } else if (content.substr(0, kFindingThenErrorOnFilePrefix.size()) ==
             kFindingThenErrorOnFilePrefix) {
    EmitFinding(diagnostic_sink, "finding_description", "finding_signature");
    const std::string trigger_path =
        content.substr(kFindingThenErrorOnFilePrefix.size());
    std::thread([diagnostic_sink, trigger_path] {
      while (!std::filesystem::exists(trigger_path)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
      EmitError(diagnostic_sink, "error_after_batch");
      std::ofstream(trigger_path + std::string{kErrorEmittedFileSuffix});
    }).detach();
  }

  const uint64_t feature = 0;
  const FuzzTestUint64sView features_view = {&feature, 1};
  sink->EmitCoverageFeatures(sink->ctx, &features_view);
}

void DeserializeInputContent(FuzzTestAdapterCtx* ctx,
                             const FuzzTestBytesView* content,
                             const FuzzTestInputSink* sink) {
  EmitInput({reinterpret_cast<const char*>(content->data), content->size},
            sink);
}

void SerializeInputContent(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input,
                           const FuzzTestBytesSink* sink) {
  const auto bytes = ToBytesView(reinterpret_cast<TestInput*>(input)->content);
  sink->Emit(sink->ctx, &bytes);
}

void FreeInput(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input) {
  auto* adapter_ctx = reinterpret_cast<AdapterCtx*>(ctx);
  const FuzzTestDiagnosticSink* diagnostic_sink = adapter_ctx->diagnostic_sink;
  auto* input_object = reinterpret_cast<TestInput*>(input);
  if (input_object->content == "finding_then_error_on_free") {
    EmitError(diagnostic_sink, "error_in_free_input");
  }
  delete input_object;
}

void FreeCtx(FuzzTestAdapterCtx* ctx) {
  delete reinterpret_cast<AdapterCtx*>(ctx);
}

void ConstructAdapter(FuzzTestAdapterManagerCtx* ctx,
                      const FuzzTestDiagnosticSink* diagnostic_sink,
                      FuzzTestAdapter* adapter_out) {
  adapter_out->ctx =
      reinterpret_cast<FuzzTestAdapterCtx*>(new AdapterCtx{diagnostic_sink});
  adapter_out->SetUpCoverageDomains = SetUpCoverageDomains;
  adapter_out->GetRandomSeedInput = GetRandomSeedInput;
  adapter_out->Mutate = Mutate;
  adapter_out->Execute = Execute;
  adapter_out->DeserializeInputContent = DeserializeInputContent;
  adapter_out->SerializeInputContent = SerializeInputContent;
  adapter_out->FreeInput = FreeInput;
  adapter_out->FreeCtx = FreeCtx;
}

}  // namespace

int main(int argc, char** argv) {
  const FuzzTestAdapterManager manager = {
      /*ctx=*/nullptr,
      /*GetBinaryId=*/nullptr,
      /*GetTestName=*/
      [](FuzzTestAdapterManagerCtx* ctx, const FuzzTestBytesSink* sink) {
        static constexpr std::string_view kTestName = "some_test";
        const auto bytes = ToBytesView(kTestName);
        sink->Emit(sink->ctx, &bytes);
      },
      /*ConstructAdapter=*/ConstructAdapter,
  };
  // This binary is only supposed to run as an engine worker.
  return FuzzTestWorkerMaybeRun(&manager) == kFuzzTestWorkerSuccess
             ? EXIT_SUCCESS
             : EXIT_FAILURE;
}
