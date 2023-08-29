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

#include "./centipede/runner_result.h"

#include <cstdint>
#include <cstring>

#include "./centipede/runner_cmp_trace.h"
#include "./centipede/shared_memory_blob_sequence.h"

namespace centipede {

namespace {
enum Tags : Blob::SizeAndTagT {
  kTagInvalid,  // 0 is an invalid tag.
  kTagFeatures,
  kTagInputBegin,
  kTagInputEnd,
  kTagStats,
  kTagMetadata,
};
}  // namespace

bool BatchResult::WriteOneFeatureVec(const feature_t *vec, size_t size,
                                     BlobSequence &blobseq) {
  return blobseq.Write({kTagFeatures, size * sizeof(vec[0]),
                        reinterpret_cast<const uint8_t *>(vec)});
}

bool BatchResult::WriteInputBegin(BlobSequence &blobseq) {
  return blobseq.Write({kTagInputBegin, 0, nullptr});
}

bool BatchResult::WriteInputEnd(BlobSequence &blobseq) {
  return blobseq.Write({kTagInputEnd, 0, nullptr});
}

bool BatchResult::WriteStats(const ExecutionResult::Stats &stats,
                             BlobSequence &blobseq) {
  return blobseq.Write(
      {kTagStats, sizeof(stats), reinterpret_cast<const uint8_t *>(&stats)});
}

bool BatchResult::WriteMetadata(const ExecutionMetadata &metadata,
                                BlobSequence &blobseq) {
  return metadata.Write(kTagMetadata, blobseq);
}

// The sequence we expect to receive is
// InputBegin, Features, Stats, InputEnd, InputBegin, ...
// with a total of results().size() tuples (InputBegin ... InputEnd).
// Blobs between InputBegin/InputEnd may go in any order.
// If the execution failed on some input, we will see InputBegin,
// but will not see all or some other blobs.
bool BatchResult::Read(BlobSequence &blobseq) {
  size_t num_begins = 0;
  size_t num_ends = 0;
  const size_t num_expected_tuples = results().size();
  ExecutionResult *current_execution_result = nullptr;
  while (true) {
    auto blob = blobseq.Read();
    if (!blob.IsValid()) break;
    if (blob.tag == kTagInputBegin) {
      if (num_begins != num_ends) return false;
      ++num_begins;
      if (num_begins > num_expected_tuples) return false;
      current_execution_result = &results()[num_ends];
      current_execution_result->clear();
      continue;
    }
    if (blob.tag == kTagInputEnd) {
      ++num_ends;
      if (num_ends != num_begins) return false;
      current_execution_result = nullptr;
      continue;
    }
    if (blob.tag == kTagMetadata) {
      current_execution_result->metadata().Read(blob);
      continue;
    }
    if (blob.tag == kTagStats) {
      if (blob.size != sizeof(ExecutionResult::Stats)) return false;
      memcpy(&current_execution_result->stats(), blob.data, blob.size);
      continue;
    }
    if (blob.tag == kTagFeatures) {
      auto features_beg = reinterpret_cast<const feature_t *>(blob.data);
      size_t features_size = blob.size / sizeof(features_beg[0]);
      FeatureVec &features = current_execution_result->mutable_features();
      // if features.capacity() >= features_size, this will not cause malloc.
      features.resize(0);
      features.insert(features.begin(), features_beg,
                      features_beg + features_size);
    }
  }
  num_outputs_read_ = num_ends;
  return true;
}

}  // namespace centipede
