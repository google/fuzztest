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
#include "./centipede/shard_reader.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/types/span.h"
#include "./centipede/blob_file.h"
#include "./centipede/defs.h"
#include "./centipede/feature.h"
#include "./centipede/util.h"

namespace centipede {

// TODO(kcc): fix this function in the following ways:
//  * Don't ignore errors other than files being empty or non-existent.
//  * Allocate as little temporary heap memory as possible.
//  * Maybe check if certain feature sets can be rejected before loading
//    the corresponding input (again, in order to reduce temporary allocations).
void ReadShard(
    std::string_view corpus_path, std::string_view features_path,
    const std::function<void(const ByteArray &, FeatureVec &)> &callback) {
  // Maps features to input's hash.
  absl::flat_hash_map<std::string, FeatureVec> hash_to_features;
  // Read all features, populate hash_to_features.
  {
    auto features_reader = DefaultBlobFileReaderFactory();
    features_reader->Open(features_path).IgnoreError();  // File may not exist.
    absl::Span<uint8_t> hash_and_features;
    while (features_reader->Read(hash_and_features).ok()) {
      // Every valid feature record must contain the hash at the end.
      // Ignore this record if it is too short.
      if (hash_and_features.size() < kHashLen) continue;

      FeatureVec features;
      std::string hash = UnpackFeaturesAndHash(hash_and_features, &features);
      if (features.empty()) {
        // Special case: zero features.
        hash_to_features[hash] = {feature_domains::kNoFeature};
        continue;
      }
      hash_to_features[hash] = features;
    }
  }
  // Read the corpus. Call `callback` for every {input, features} pair.
  auto corpus_reader = DefaultBlobFileReaderFactory();
  corpus_reader->Open(corpus_path).IgnoreError();  // File may not exist.
  absl::Span<uint8_t> blob;
  while (corpus_reader->Read(blob).ok()) {
    callback(ByteArray(blob.begin(), blob.end()), hash_to_features[Hash(blob)]);
  }
}

}  // namespace centipede
