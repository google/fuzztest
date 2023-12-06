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
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "./centipede/blob_file.h"
#include "./centipede/defs.h"
#include "./centipede/feature.h"
#include "./centipede/logging.h"
#include "./centipede/remote_file.h"
#include "./centipede/util.h"

namespace centipede {

// TODO(kcc): fix this function in the following ways:
//  * Allocate as little temporary heap memory as possible.
//  * Maybe check if certain feature sets can be rejected before loading
//    the corresponding input (again, in order to reduce temporary allocations).
//  * Change the callback signature to take two r-values and std::move both
//    params when calling it.
//  * When the above is done, stop inserting empty `FeatureVec`s into
//    `hash_to_features` when invoking the callback, just pass {}.
void ReadShard(
    std::string_view corpus_path, std::string_view features_path,
    const std::function<void(const ByteArray &, FeatureVec &)> &callback) {
  const bool good_corpus_path =
      !corpus_path.empty() && RemotePathExists(corpus_path);
  const bool good_features_path =
      !features_path.empty() && RemotePathExists(features_path);

  if (!good_corpus_path) {
    VLOG(1) << __func__
            << "(): Corpus file path empty or not found - returning: "
            << corpus_path;
    return;
  }

  // Maps features to input's hash.
  absl::flat_hash_map<std::string, FeatureVec> hash_to_features;

  // Read all features, populate hash_to_features.
  // If the file is not passed or doesn't exist, simply ignore it.
  if (!good_features_path) {
    VLOG(1) << __func__
            << "(): Features file path empty or not found - ignoring: "
            << features_path;
  } else {
    auto features_reader = DefaultBlobFileReaderFactory();
    CHECK_OK(features_reader->Open(features_path)) << VV(features_path);
    ByteSpan hash_and_features;
    while (features_reader->Read(hash_and_features).ok()) {
      // Every valid feature record must contain the hash at the end.
      // Ignore this record if it is too short.
      if (hash_and_features.size() < kHashLen) continue;
      FeatureVec features;
      std::string hash = UnpackFeaturesAndHash(hash_and_features, &features);
      if (features.empty()) {
        // When the features file got created, Centipede did compute features
        // for the input, but they came up empty. Indicate to the client that
        // there is no need to recompute by returning this special value.
        features = {feature_domains::kNoFeature};
      }
      hash_to_features.emplace(std::move(hash), std::move(features));
    }
  }

  // Read the corpus. Call `callback` for every {input, features} pair.
  auto corpus_reader = DefaultBlobFileReaderFactory();
  CHECK_OK(corpus_reader->Open(corpus_path)) << VV(corpus_path);
  ByteSpan blob;
  while (corpus_reader->Read(blob).ok()) {
    ByteArray input{blob.begin(), blob.end()};
    // In contrast to `{feature_domains::kNoFeature}` above, if features for
    // this input were not computed or recorded, the line below will insert
    // a truly empty value into `hash_to_features`, allowing the client to
    // discern these two cases.
    FeatureVec &features = hash_to_features[Hash(blob)];
    callback(input, features);
  }
}

}  // namespace centipede
