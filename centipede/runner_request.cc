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
#include <vector>

#include "./centipede/defs.h"
#include "./centipede/shared_memory_blob_sequence.h"

namespace centipede {

namespace {

enum Tags : Blob::SizeAndTagT {
  kTagInvalid,  // 0 is an invalid tag.
  kTagExecution,
  kTagSeed,
  kTagMutation,
  kTagNumInputs,
  kTagNumSeeds,
  kTagNumMutants,
  kTagExecutionMetadata,
  kTagDataInput,
};

// Writes `inputs` to `blobseq`, returns the number of inputs written.
static size_t WriteInputs(const std::vector<ByteArray> &inputs,
                          BlobSequence &blobseq) {
  size_t num_inputs = inputs.size();
  if (!blobseq.Write(kTagNumInputs, num_inputs)) return 0;
  size_t result = 0;
  for (const auto &input : inputs) {
    if (!blobseq.Write({kTagDataInput, input.size(), input.data()}))
      return result;
    ++result;
  }
  return result;
}

static bool WriteMetadataFromRefOrDefault(const ExecutionMetadata *metadata,
                                          BlobSequence &blobseq) {
  if (metadata != nullptr)
    return metadata->Write(kTagExecutionMetadata, blobseq);
  static const ExecutionMetadata *default_metadata = new ExecutionMetadata();
  return default_metadata->Write(kTagExecutionMetadata, blobseq);
}

// Similar to above, but for mutation inputs.
static size_t WriteInputs(const std::vector<MutationInputRef> &inputs,
                          BlobSequence &blobseq) {
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

namespace runner_request {

size_t RequestExecution(const std::vector<ByteArray> &inputs,
                        BlobSequence &blobseq) {
  if (!blobseq.Write({kTagExecution, 0, nullptr})) return 0;
  return WriteInputs(inputs, blobseq);
}

bool RequestSeeds(size_t num_seeds, BlobSequence &blobseq) {
  if (!blobseq.Write({kTagSeed, 0, nullptr})) return false;
  if (!blobseq.Write(kTagNumSeeds, num_seeds)) return false;
  return true;
}

size_t RequestMutation(size_t num_mutants,
                       const std::vector<MutationInputRef> &inputs,
                       BlobSequence &blobseq) {
  if (!blobseq.Write({kTagMutation, 0, nullptr})) return 0;
  if (!blobseq.Write(kTagNumMutants, num_mutants)) return 0;
  return WriteInputs(inputs, blobseq);
}

bool IsExecutionRequest(Blob blob) { return blob.tag == kTagExecution; }

bool IsSeedRequest(Blob blob) { return blob.tag == kTagSeed; }

bool IsMutationRequest(Blob blob) { return blob.tag == kTagMutation; }

bool IsNumInputs(Blob blob, size_t &num_inputs) {
  if (blob.tag != kTagNumInputs) return false;
  if (blob.size != sizeof(num_inputs)) return false;
  memcpy(&num_inputs, blob.data, sizeof(num_inputs));
  return true;
}

bool IsNumSeeds(Blob blob, size_t &num_seeds) {
  if (blob.tag != kTagNumSeeds) return false;
  if (blob.size != sizeof(num_seeds)) return false;
  memcpy(&num_seeds, blob.data, sizeof(num_seeds));
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
  metadata.Read(blob);
  return true;
}

bool IsDataInput(Blob blob) { return blob.tag == kTagDataInput; }

}  // namespace runner_request

}  // namespace centipede
