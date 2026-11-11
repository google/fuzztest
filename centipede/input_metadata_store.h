// Copyright 2026 The Centipede Authors.
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

// Controller-side storage of persistent input metadata.
//
// Persistent input metadata is opaque data that the test attaches to an input
// when executing it (see `ExecutionMetadata::persistent_data`). The engine
// stores it per input and passes it back to the test before the next execution
// of the same input. The engine never interprets it.
//
// The metadata of an input is stored in the file
//
//   <fuzztest_persistent_metadata_root>/<fuzztest_binary_identifier>/
//       <test_name>/<hash>
//
// where <hash> is `Hash()` of the input bytes.

#ifndef FUZZTEST_CENTIPEDE_INPUT_METADATA_STORE_H_
#define FUZZTEST_CENTIPEDE_INPUT_METADATA_STORE_H_

#include <string>
#include <vector>

#include "absl/types/span.h"
#include "./centipede/environment.h"
#include "./centipede/runner_result.h"
#include "./common/defs.h"

namespace fuzztest::internal {

class InputMetadataStore {
 public:
  // The store is enabled iff `env.fuzztest_persistent_metadata_root` is
  // non-empty.
  explicit InputMetadataStore(const Environment& env);

  bool enabled() const { return !dir_.empty(); }

  // Returns the directory with the metadata files, or empty if disabled.
  const std::string& dir() const { return dir_; }

  // Returns the stored metadata of each of `inputs`, in the same order. The
  // metadata of an input without stored metadata is empty. Returns an empty
  // vector if the store is disabled. Crashes on I/O errors.
  std::vector<ByteArray> Load(absl::Span<const ByteSpan> inputs) const;

  // Stores the persistent metadata in the results of `batch_result` that were
  // read after executing `inputs`. Results without persistent metadata leave
  // the stored metadata of their inputs unchanged. No-op if the store is
  // disabled. Crashes on I/O errors.
  void Save(absl::Span<const ByteSpan> inputs, const BatchResult& batch_result);

 private:
  // Empty if the store is disabled.
  const std::string dir_;
  bool dir_created_ = false;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_CENTIPEDE_INPUT_METADATA_STORE_H_
