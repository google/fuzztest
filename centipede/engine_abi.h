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

#ifndef FUZZTEST_CENTIPEDE_ENGINE_ABI_H_
#define FUZZTEST_CENTIPEDE_ENGINE_ABI_H_

// FuzzTest engine ABI.
//
// This header needs to be C-compatible.

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handles for in-memory input objects used by the test, which
// may be serialized/deserialized by the engine.
typedef uintptr_t FuzzTestInputHandle;

typedef struct {
  const uint8_t* data;
  size_t size;
} FuzzTestBytesView;

// Sink for diagnostics during the setup and execution of the test
// methods. Methods in this sink are async-safe and thread-safe.
typedef struct FuzzTestDiagnosticSinkCtx FuzzTestDiagnosticSinkCtx;
typedef struct {
  FuzzTestDiagnosticSinkCtx* ctx;

  // Emits an unrecoverable error with a human-readable `message`. Engine would
  // propagate the error to the controller command when in the worker mode.
  void (*EmitError)(FuzzTestDiagnosticSinkCtx* ctx,
                    const FuzzTestBytesView* message);

  // Emits a warning with a human-readable `message`. Engine would log
  // the warning and continue gracefully when in the worker mode.
  void (*EmitWarning)(FuzzTestDiagnosticSinkCtx* ctx,
                      const FuzzTestBytesView* message);

  // Emits a finding for running a test input within `Execute()` with a
  // human-readable `description`, and `signature` for deduplication.
  //
  // Must not be called if the engine is not calling `Execute()`. If called
  // multiple times within the same `Execute()` window, a random one would take
  // effect.
  void (*EmitFinding)(FuzzTestDiagnosticSinkCtx* ctx,
                      const FuzzTestBytesView* description,
                      const FuzzTestBytesView* signature);
} FuzzTestDiagnosticSink;

// Sink for bytes data.
typedef struct FuzzTestBytesSinkCtx FuzzTestBytesSinkCtx;
typedef struct {
  FuzzTestBytesSinkCtx* ctx;

  // Emits a byte buffer. Multiple emissions are concatenated.
  void (*Emit)(FuzzTestBytesSinkCtx* ctx, const FuzzTestBytesView* view);
} FuzzTestBytesSink;

// Sink for seed inputs.
typedef struct FuzzTestInputSinkCtx FuzzTestInputSinkCtx;
typedef struct {
  FuzzTestInputSinkCtx* ctx;

  // Emits a test `input` to the engine. Engine would call
  // `FuzzTestAdapter::FreeInput` on the emitted input after the engine is
  // done with it.
  void (*Emit)(FuzzTestInputSinkCtx* ctx, FuzzTestInputHandle input);
} FuzzTestInputSink;

typedef struct {
  const uint64_t* data;
  size_t size;
} FuzzTestUint64sView;

// Constants for the layout of the coverage feature as a 64-bit unsigned
// integer:
//
//   - Bits 63..59: 5-bit domain ID of the feature. Each domain is a
//     logically independent feature namespace registered in
//     `FuzzTestAdapter::SetUpCoverageDomains`.
//   - Bits 58..32: 27-bit feature ID within the domain.
//   - Bits 31..0:  32-bit counter value of the feature.
//
typedef enum {
  kFuzzTestCoverageCounterStartBit = 0,
  kFuzzTestCoverageCounterBitSize = 32,
  kFuzzTestCoverageFeatureIdStartBit = 32,
  kFuzzTestCoverageFeatureIdBitSize = 27,
  kFuzzTestCoverageDomainIdStartBit = 59,
  kFuzzTestCoverageDomainIdBitSize = 5,
} FuzzTestCoverageFeatureLayout;

// Sink for execution feedback.
typedef struct FuzzTestFeedbackSinkCtx FuzzTestFeedbackSinkCtx;
typedef struct {
  FuzzTestFeedbackSinkCtx* ctx;

  // Emits an array of coverage features captured from the execution
  // inside `Execute` call. See `FuzzTestCoverageFeatureLayout` for the feature
  // layout.
  //
  // Multiple emissions are concatenated.
  void (*EmitCoverageFeatures)(FuzzTestFeedbackSinkCtx* ctx,
                               const FuzzTestUint64sView* features);
} FuzzTestFeedbackSink;

// Information of a coverage domain.
typedef struct {
  // 5-bit domain ID.
  uint8_t domain_id;
  // Human-readable name of the domain for logging.
  FuzzTestBytesView name;
  // Number of bits used for the feature IDs in this domain, must be <= 27.
  uint8_t feature_id_bit_size;
  // Number of bits used for the counter values in this domain, must be <= 32.
  uint8_t counter_bit_size;
} FuzzTestCoverageDomain;

typedef struct FuzzTestCoverageDomainRegistryCtx
    FuzzTestCoverageDomainRegistryCtx;
typedef struct {
  FuzzTestCoverageDomainRegistryCtx* ctx;

  // Registers a new coverage `domain`.
  void (*Register)(FuzzTestCoverageDomainRegistryCtx* ctx,
                   const FuzzTestCoverageDomain* domain);
} FuzzTestCoverageDomainRegistry;

typedef struct FuzzTestAdapterCtx FuzzTestAdapterCtx;
typedef struct FuzzTestAdapter {
  FuzzTestAdapterCtx* ctx;

  // Sets up coverage domains using the domain `registry`.
  // The domain registrations must be the same for the all the test adapters of
  // the same test (identified by the test name and the binary).
  void (*SetUpCoverageDomains)(FuzzTestAdapterCtx* ctx,
                               const FuzzTestCoverageDomainRegistry* registry);

  // [Optional] Emits any preset seed inputs of the test using `sink`.
  // The output must be the same for the all the test adapters of the same test
  // (identified by the test name and the binary).
  void (*GetPresetSeedInputs)(FuzzTestAdapterCtx* ctx,
                              const FuzzTestInputSink* sink);

  // Emits a randomly generated seed input using `sink`.
  void (*GetRandomSeedInput)(FuzzTestAdapterCtx* ctx,
                             const FuzzTestInputSink* sink);

  // Mutates from `origin`, and emits the mutant using `sink`. `shrink` != 0
  // means to generate smaller mutant.
  //
  // It should not change the content/metadata of `origin`.
  void (*Mutate)(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle origin,
                 int shrink, const FuzzTestInputSink* sink);

  // [Optional] Performs cross-over mutation using `origin` and `other`, and
  // emits the mutant using `sink`.
  //
  // It should not change the content/metadata of `origin` or `other`.
  void (*CrossOver)(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle origin,
                    FuzzTestInputHandle other, const FuzzTestInputSink* sink);

  // Executes `input` for testing and emits any feedback to `sink`.
  //
  // The `input` metadata may be updated by the adapter for further
  // mutations. The `input` content, which affects the test behavior of
  // `Execute()`, should not be changed.
  void (*Execute)(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input,
                  const FuzzTestFeedbackSink* sink);

  // Serializes the test `input` content into bytes using `sink`.
  void (*SerializeInputContent)(FuzzTestAdapterCtx* ctx,
                                FuzzTestInputHandle input,
                                const FuzzTestBytesSink* sink);

  // Deserializes the test `input` content from serialized `content` into
  // a `FuzzTestInputHandle` using `sink`.
  void (*DeserializeInputContent)(FuzzTestAdapterCtx* ctx,
                                  const FuzzTestBytesView* content,
                                  const FuzzTestInputSink* sink);

  // [Optional] Serializes the test `input` metadata into bytes using `sink`.
  void (*SerializeInputMetadata)(FuzzTestAdapterCtx* ctx,
                                 FuzzTestInputHandle input,
                                 const FuzzTestBytesSink* sink);

  // [Optional] Updates the test `input` metadata from serialized `metadata`.
  void (*UpdateInputMetadata)(FuzzTestAdapterCtx* ctx,
                              const FuzzTestBytesView* metadata,
                              FuzzTestInputHandle input);

  // Callback to run when the engine is done with `input`.
  void (*FreeInput)(FuzzTestAdapterCtx* ctx, FuzzTestInputHandle input);

  // Callback to run when the engine is done with `ctx` (and the adapter).
  void (*FreeCtx)(FuzzTestAdapterCtx* ctx);
} FuzzTestAdapter;

typedef struct FuzzTestAdapterManagerCtx FuzzTestAdapterManagerCtx;
typedef struct {
  FuzzTestAdapterManagerCtx* ctx;

  // [Optional] Emits the ID for the current binary.
  void (*GetBinaryId)(FuzzTestAdapterManagerCtx* ctx,
                      const FuzzTestBytesSink* sink);

  // Emits the test name.
  void (*GetTestName)(FuzzTestAdapterManagerCtx* ctx,
                      const FuzzTestBytesSink* sink);

  // Constructs an adapter of the test into `adapter_out`. Any diagnostics
  // happening during the construction or running the adapter should be emitted
  // to `diagnostic_sink`. `diagnostic_sink` is guaranteed to live until
  // `FreeCtx` is called on the adapter.
  void (*ConstructAdapter)(FuzzTestAdapterManagerCtx* ctx,
                           const FuzzTestDiagnosticSink* diagnostic_sink,
                           FuzzTestAdapter* adapter_out);
} FuzzTestAdapterManager;

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // FUZZTEST_CENTIPEDE_ENGINE_ABI_H_
