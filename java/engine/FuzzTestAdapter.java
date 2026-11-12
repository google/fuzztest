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
 * Framework-neutral Java adapter corresponding to {@code FuzzTestAdapter} in {@code
 * centipede/engine_abi.h}.
 *
 * <p>In-memory test inputs are represented as opaque 64-bit {@code long} handles owned by the
 * adapter until the engine invokes {@link #freeInput(long)}.
 */
public interface FuzzTestAdapter {

  /**
   * Registry callback used during {@link #setUpCoverageDomains} to declare packed 64-bit coverage
   * feature domains ({@code FuzzTestCoverageDomainRegistry} in {@code engine_abi.h}).
   */
  @FunctionalInterface
  interface CoverageDomainRegistry {
    /**
     * Registers a coverage domain with 5-bit {@code domainId} ({@code 0..31}), human-readable
     * {@code name}, {@code featureIdBitSize} ({@code 0..27}), and {@code counterBitSize} ({@code
     * 0..32}).
     */
    void register(int domainId, String name, int featureIdBitSize, int counterBitSize);
  }

  /** Registers deterministic coverage domains for this test ({@code SetUpCoverageDomains}). */
  default void setUpCoverageDomains(CoverageDomainRegistry registry) {}

  /**
   * Returns deterministic preset seed input handles for this test ({@code GetPresetSeedInputs}).
   */
  default long[] presetSeedInputs() {
    return new long[0];
  }

  /**
   * Allocates and returns one randomly generated seed input handle ({@code GetRandomSeedInput}).
   */
  long randomSeedInput();

  /**
   * Mutates {@code origin} into a newly allocated handle without modifying {@code origin}'s content
   * or metadata ({@code Mutate}). When {@code shrink} is {@code true}, favors complexity-reducing
   * mutations.
   */
  long mutate(long origin, boolean shrink);

  /**
   * Produces a crossover mutant from {@code origin} and {@code other} in a newly allocated handle
   * without modifying either input ({@code CrossOver}).
   */
  long crossOver(long origin, long other);

  /**
   * Executes {@code input} for a single trial and returns packed 64-bit coverage features ({@code
   * Execute}). Must not modify {@code input}'s serialized content, though adapter-side execution
   * metadata on {@code input} may be updated.
   */
  long[] execute(long input);

  /** Serializes {@code input}'s content into non-empty bytes ({@code SerializeInputContent}). */
  byte[] serializeInputContent(long input);

  /**
   * Deserializes {@code content} into a newly allocated input handle ({@code
   * DeserializeInputContent}).
   */
  long deserializeInputContent(byte[] content);

  /**
   * Serializes optional execution metadata recorded on {@code input}, or returns an empty array
   * ({@code SerializeInputMetadata}).
   */
  default byte[] serializeInputMetadata(long input) {
    return new byte[0];
  }

  /**
   * Restores serialized execution {@code metadata} onto {@code input} without altering its content
   * ({@code UpdateInputMetadata}).
   */
  default void updateInputMetadata(byte[] metadata, long input) {}

  /** Releases {@code input} once the engine is done with it ({@code FreeInput}). */
  void freeInput(long input);

  /** Releases adapter-level resources when the worker finishes ({@code FreeCtx}). */
  default void close() {}
}
