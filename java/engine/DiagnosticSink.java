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

package com.google.fuzztest.engine;

/**
 * Diagnostic and finding sink bridging Java fuzz-test adapters to {@code FuzzTestDiagnosticSink} in
 * {@code centipede/engine_abi.h}.
 *
 * <p>The sink passed to {@link FuzzTestAdapterManager#constructAdapter(DiagnosticSink)} remains
 * valid until {@link FuzzTestAdapter#close()} completes.
 */
public interface DiagnosticSink {

  /**
   * Emits an unrecoverable setup or adapter error with a human-readable {@code message}, which the
   * engine propagates to the controller when running in worker mode.
   */
  void emitError(String message);

  /** Emits a non-fatal warning {@code message} while continuing execution in worker mode. */
  void emitWarning(String message);

  /**
   * Emits a test finding with a human-readable {@code description} and deduplication {@code
   * signature}.
   *
   * <p>Per {@code engine_abi.h}, findings are only valid while {@link
   * FuzzTestAdapter#execute(long)} is active; calls outside {@code execute} are treated as adapter
   * errors.
   */
  void emitFinding(String description, String signature);
}
