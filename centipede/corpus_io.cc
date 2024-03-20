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
#include "./centipede/corpus_io.h"

#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/time/time.h"
#include "./centipede/blob_file.h"
#include "./centipede/defs.h"
#include "./centipede/feature.h"
#include "./centipede/logging.h"
#include "./centipede/remote_file.h"
#include "./centipede/rusage_profiler.h"
#include "./centipede/util.h"

namespace centipede {

void ReadShard(std::string_view corpus_path, std::string_view features_path,
               const std::function<void(ByteArray, FeatureVec)> &callback) {
  const bool good_corpus_path =
      !corpus_path.empty() && RemotePathExists(corpus_path);
  const bool good_features_path =
      !features_path.empty() && RemotePathExists(features_path);

  if (!good_corpus_path) {
    LOG(WARNING) << "Corpus file path empty or not found - returning: "
                 << corpus_path;
    return;
  }

  RPROF_THIS_FUNCTION_WITH_TIMELAPSE(            //
      /*enable=*/ABSL_VLOG_IS_ON(10),            //
      /*timelapse_interval=*/absl::Seconds(30),  //
      /*also_log_timelapses=*/false);

  // Maps input hashes to inputs.
  // NOTE: Using `std::multimap` to prevent auto-deduplication of inputs.
  // TODO(ussuri): This is the legacy behavior. At least one test relies on
  //  it (but doesn't really need it). Investigate and switch to
  //  `absl::flat_hash_map`.
  std::multimap<std::string /*hash*/, ByteArray /*input*/> hash_to_input;

  // Read inputs from the corpus file into `hash_to_input`.
  auto corpus_reader = DefaultBlobFileReaderFactory();
  CHECK_OK(corpus_reader->Open(corpus_path)) << VV(corpus_path);

  // Input counts of various kinds (for logging).
  size_t num_inputs = 0;
  size_t num_inputs_missing_features = 0;
  size_t num_inputs_empty_features = 0;
  size_t num_inputs_non_empty_features = 0;

  // If the features file is not passed or doesn't exist, simply ignore it.
  if (!good_features_path) {
    LOG(WARNING) << "Features file path empty or not found - ignoring: "
                 << features_path;
  } else {
    // Read features from the features file. For each feature, find a matching
    // input in `hash_to_input`, call `callback` for the pair, and remove the
    // entry from `hash_to_input`. In the end, `hash_to_input` will contain
    // only inputs without matching features.
    auto features_reader = DefaultBlobFileReaderFactory();
    CHECK_OK(features_reader->Open(features_path)) << VV(features_path);
    ByteSpan features_blob;
    while (features_reader->Read(features_blob).ok()) {
      // Every valid feature record must contain the hash at the end.
      // Ignore this record if it is too short.
      if (features_blob.size() < kHashLen) continue;

      FeatureVec features;
      const std::string feature_hash =
          UnpackFeaturesAndHash(features_blob, &features);

      ByteArray matching_input;
      if (auto input_node = hash_to_input.extract(feature_hash);
          !input_node.empty()) {
        // A matching input has already been scanned in during one of the
        // previous lookaheads: use it.
        matching_input = std::move(input_node.mapped());
      } else {
        // A matching input has not been found during the previous lookaheads:
        // perform a new one, storing mismatching inputs into the has map along
        // the way.
        ByteSpan input_blob;
        while (corpus_reader->Read(input_blob).ok()) {
          ++num_inputs;
          std::string input_hash = Hash(input_blob);
          ByteArray input{input_blob.begin(), input_blob.end()};
          if (input_hash == feature_hash) {
            matching_input = std::move(input);
            break;
          } else {
            hash_to_input.emplace(std::move(input_hash), std::move(input));
          }
        }
      }

      if (!matching_input.empty()) {
        if (!features.empty()) {
          // A "normal" input with non-empty features.
          ++num_inputs_non_empty_features;
        } else {
          // Centipede computed empty features for this input previously.
          // Indicate to the client that it doesn't need to recompute them by
          // passing this special value.
          features = {feature_domains::kNoFeature};
          ++num_inputs_empty_features;
        }
        callback(std::move(matching_input), std::move(features));
      }
    }

    RPROF_SNAPSHOT("Read features & reported input/features pairs");
  }

  // Finally, call `callback` on the inputs without matching features, which we
  // have accumulated during lookaheads. This also automatically covers the case
  // of a features file not passed or missing.
  num_inputs_missing_features = hash_to_input.size();
  for (auto &&[hash, input] : hash_to_input) {
    // Indicate to the client that it needs to recompute features for this input
    // by passing an empty value.
    callback(std::move(input), {});
  }

  RPROF_SNAPSHOT("Reported inputs with no matching features");

  VLOG(1)  //
      << "Finished shard reading:\n"
      << "Corpus path                : " << corpus_path << "\n"
      << "Features path              : " << features_path << "\n"
      << "Inputs                     : " << num_inputs << "\n"
      << "Inputs, non-empty features : " << num_inputs_non_empty_features
      << "\n"
      << "Inputs, empty features     : " << num_inputs_empty_features << "\n"
      << "Inputs, missing features   : " << num_inputs_missing_features;
}

}  // namespace centipede
