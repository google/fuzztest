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

#include "./centipede/execution_request.h"

#include <cstring>
#include <vector>

#include "./centipede/shared_memory_blob_sequence.h"

namespace centipede {

namespace {

enum Tags : SharedMemoryBlobSequence::Blob::SizeAndTagT {
  kTagInvalid,  // 0 is an invalid tag.
  kTagExecution,
  kTagMutation,
  kTagNumInputs,
  kTagNumMutants,
  kTagDataInput,
};

// Writes `inputs` to `blobseq`, returns the number of inputs written.
static size_t WriteInputs(const std::vector<ByteArray> &inputs,
                          SharedMemoryBlobSequence &blobseq) {
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

}  // namespace

namespace execution_request {

size_t RequestExecution(const std::vector<ByteArray> &inputs,
                        SharedMemoryBlobSequence &blobseq) {
  if (!blobseq.Write({kTagExecution, 0, nullptr})) return 0;
  return WriteInputs(inputs, blobseq);
}

size_t RequestMutation(size_t num_mutants, const std::vector<ByteArray> &inputs,
                       SharedMemoryBlobSequence &blobseq) {
  if (!blobseq.Write({kTagMutation, 0, nullptr})) return 0;
  if (!blobseq.Write(kTagNumMutants, num_mutants)) return 0;
  return WriteInputs(inputs, blobseq);
}

bool IsExecutionRequest(SharedMemoryBlobSequence::Blob blob) {
  return blob.tag == kTagExecution;
}

bool IsMutationRequest(SharedMemoryBlobSequence::Blob blob) {
  return blob.tag == kTagMutation;
}

bool IsNumInputs(SharedMemoryBlobSequence::Blob blob, size_t &num_inputs) {
  if (blob.tag != kTagNumInputs) return false;
  if (blob.size != sizeof(num_inputs)) return false;
  memcpy(&num_inputs, blob.data, sizeof(num_inputs));
  return true;
}

bool IsNumMutants(SharedMemoryBlobSequence::Blob blob, size_t &num_mutants) {
  if (blob.tag != kTagNumMutants) return false;
  if (blob.size != sizeof(num_mutants)) return false;
  memcpy(&num_mutants, blob.data, sizeof(num_mutants));
  return true;
}

bool IsDataInput(SharedMemoryBlobSequence::Blob blob) {
  return blob.tag == kTagDataInput;
}

}  // namespace execution_request

}  // namespace centipede
