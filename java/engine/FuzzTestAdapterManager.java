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
 * Factory and test-identity descriptor corresponding to {@code FuzzTestAdapterManager} in {@code
 * centipede/engine_abi.h}.
 */
public interface FuzzTestAdapterManager {

  /** Returns the identifier of the current test binary ({@code GetBinaryId}). */
  default String binaryId() {
    return "";
  }

  /**
   * Returns the canonical test name matching the controller's {@code --test_name} flag ({@code
   * GetTestName}).
   */
  String testName();

  /**
   * Constructs a {@link FuzzTestAdapter} for {@link #testName()} bound to {@code diagnosticSink}
   * ({@code ConstructAdapter}).
   */
  FuzzTestAdapter constructAdapter(DiagnosticSink diagnosticSink);
}
