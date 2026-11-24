// Copyright 2022 The Centipede Authors.
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

#include "./centipede/runner_request.h"

#include <cstring>

#include "absl/types/span.h"
#include "./centipede/mutation_data.h"
#include "./centipede/shared_memory_blob_sequence.h"
#include "./common/defs.h"
#include "./framework_shared/internal/execution_metadata.h"

namespace fuzztest::internal {

namespace {

enum Tags : Blob::SizeAndTagT {
  kTagInvalid,  // 0 is an invalid tag.
  kTagExecution,
  kTagMutation,
  kTagNumInputs,
  kTagNumMutants,
  kTagExecutionMetadata,
  kTagDataInput,
  kTagPersistentMetadata,
};

// Writes `inputs` to `blobseq`, returns the number of inputs written.
// `persistent_metadata` is either empty or has the same size as `inputs`; a
// non-empty `persistent_metadata[i]` is written before `inputs[i]`.
static size_t WriteInputs(absl::Span<const ByteSpan> inputs,
                          absl::Span<const ByteSpan> persistent_metadata,
                          BlobSequence& blobseq) {
  size_t num_inputs = inputs.size();
  if (!blobseq.Write(kTagNumInputs, num_inputs)) return 0;
  size_t result = 0;
  for (size_t i = 0; i < inputs.size(); ++i) {
    if (i < persistent_metadata.size() && !persistent_metadata[i].empty() &&
        !blobseq.Write({kTagPersistentMetadata, persistent_metadata[i].size(),
                        persistent_metadata[i].data()})) {
      return result;
    }
    if (!blobseq.Write({kTagDataInput, inputs[i].size(), inputs[i].data()}))
      return result;
    ++result;
  }
  return result;
}

static bool WriteMetadataFromRefOrDefault(const ExecutionMetadata *metadata,
                                          BlobSequence &blobseq) {
  if (metadata != nullptr) {
    return blobseq.Write({kTagExecutionMetadata, metadata->cmp_data.size(),
                          metadata->cmp_data.data()});
  }
  return blobseq.Write({kTagExecutionMetadata, 0, nullptr});
}

// Similar to above, but for mutation inputs.
static size_t WriteInputs(absl::Span<const MutationInputRef> inputs,
                          BlobSequence& blobseq) {
  size_t num_inputs = inputs.size();
  if (!blobseq.Write(kTagNumInputs, num_inputs)) return 0;
  size_t result = 0;
  for (const auto &input : inputs) {
    if (!WriteMetadataFromRefOrDefault(input.metadata, blobseq)) return result;
    if (!blobseq.Write({kTagDataInput, input.data.size(), input.data.data()}))
      return result;
    ++result;
  }
  return result;
}

}  // namespace

size_t RequestExecution(absl::Span<const ByteSpan> inputs,
                        BlobSequence& blobseq) {
  return RequestExecution(inputs, /*persistent_metadata=*/{}, blobseq);
}

size_t RequestExecution(absl::Span<const ByteSpan> inputs,
                        absl::Span<const ByteSpan> persistent_metadata,
                        BlobSequence& blobseq) {
  if (!persistent_metadata.empty() &&
      persistent_metadata.size() != inputs.size()) {
    return 0;
  }
  if (!blobseq.Write({kTagExecution, 0, nullptr})) return 0;
  return WriteInputs(inputs, persistent_metadata, blobseq);
}

size_t RequestMutation(size_t num_mutants,
                       absl::Span<const MutationInputRef> inputs,
                       BlobSequence& blobseq) {
  if (!blobseq.Write({kTagMutation, 0, nullptr})) return 0;
  if (!blobseq.Write(kTagNumMutants, num_mutants)) return 0;
  return WriteInputs(inputs, blobseq);
}

bool IsExecutionRequest(Blob blob) { return blob.tag == kTagExecution; }

bool IsMutationRequest(Blob blob) { return blob.tag == kTagMutation; }

bool IsNumInputs(Blob blob, size_t &num_inputs) {
  if (blob.tag != kTagNumInputs) return false;
  if (blob.size != sizeof(num_inputs)) return false;
  memcpy(&num_inputs, blob.data, sizeof(num_inputs));
  return true;
}

bool IsNumMutants(Blob blob, size_t &num_mutants) {
  if (blob.tag != kTagNumMutants) return false;
  if (blob.size != sizeof(num_mutants)) return false;
  memcpy(&num_mutants, blob.data, sizeof(num_mutants));
  return true;
}

bool IsExecutionMetadata(Blob blob, ExecutionMetadata &metadata) {
  if (blob.tag != kTagExecutionMetadata) return false;
  metadata.cmp_data.assign(blob.data, blob.data + blob.size);
  return true;
}

bool IsPersistentMetadata(Blob blob) {
  return blob.tag == kTagPersistentMetadata;
}

bool IsDataInput(Blob blob) { return blob.tag == kTagDataInput; }

}  // namespace fuzztest::internal
