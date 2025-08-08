// Copyright 2024 The Centipede Authors.
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

// A simple tool for analyzing a centipede features file.
//
// Extracts all features for a given user domain and writes them to LOG(INFO)
//
// Usage:
//  feature_analyzer --user_domain=1 \
//  --feature_file=/tmp/wd/features.000000 >  out.txt
//
#include <cstddef>
#include <iostream>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "./centipede/feature.h"
#include "./centipede/util.h"
#include "./common/blob_file.h"
#include "./common/defs.h"

ABSL_FLAG(std::string, feature_file, "", "Path to the feature file to read");

ABSL_FLAG(size_t, user_domain, 0, "User Feature Domain to section out");

namespace fuzztest::internal {

// Read all the features from the file and return them to the caller.
absl::StatusOr<FeatureVec> ReadFeaturesFile(absl::string_view features_path) {
  auto features_reader = DefaultBlobFileReaderFactory();
  absl::Status read_status = features_reader->Open(features_path);
  if (!read_status.ok()) {
    std::cerr << "Could not read from file: " << features_path << std::endl;
    return read_status;
  }
  ByteSpan blob;
  FeatureVec aggregated_features;
  while (features_reader->Read(blob).ok()) {
    FeatureVec features;
    UnpackFeaturesAndHash(blob, &features);
    for (auto feature : features) {
      aggregated_features.push_back(feature);
    }
  }
  return aggregated_features;
}

absl::Status FeatureAnalyzerMain() {
  size_t user_domain = absl::GetFlag(FLAGS_user_domain);
  CHECK_LT(user_domain, feature_domains::kUserDomains.size());
  size_t goal_domain = feature_domains::kUserDomains[user_domain].domain_id();

  absl::StatusOr<FeatureVec> features_or =
      ReadFeaturesFile(absl::GetFlag(FLAGS_feature_file));
  if (!features_or.ok()) {
    return features_or.status();
  }

  for (auto feature : *features_or) {
    size_t domain_id = feature_domains::Domain::FeatureToDomainId(feature);
    size_t index_in_domain =
        feature_domains::Domain::FeatureToIndexInDomain(feature);
    if (domain_id == goal_domain) {
      // Since a feature in user domain zero with an id of zero would typically
      // be skipped, silifuzz increments all of the values for domain zero by 1
      // so that they are not skipped due to being all zeros.
      if (user_domain == 0) {
        index_in_domain--;
      }
      std::cout << "domain: " << domain_id << " feature: " << index_in_domain
                << std::endl;
    }
  }
  std::cout << "total number of features: " << features_or->size() << std::endl;
  return absl::OkStatus();
}

}  // namespace fuzztest::internal

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  auto status = fuzztest::internal::FeatureAnalyzerMain();
  if (!status.ok()) {
    std::cerr << status.error_message() << std::endl;
    return 1;
  }
  return 0;
}
