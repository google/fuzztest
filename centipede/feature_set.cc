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

#include "./centipede/feature_set.h"

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include "./centipede/feature.h"

namespace centipede {

//------------------------------------------------------------------------------
//                                FeatureSet
//------------------------------------------------------------------------------

// TODO(kcc): [impl] add tests.
PCIndexVec FeatureSet::ToCoveragePCs() const {
  return {pc_index_set_.begin(), pc_index_set_.end()};
}

size_t FeatureSet::CountFeatures(feature_domains::Domain domain) {
  return features_per_domain_[domain.domain_id()];
}

__attribute__((noinline))  // to see it in profile.
size_t
FeatureSet::CountUnseenAndPruneFrequentFeatures(FeatureVec &features) const {
  size_t number_of_unseen_features = 0;
  size_t num_kept = 0;
  for (size_t i = 0, n = features.size(); i < n; i++) {
    auto feature = features[i];
    auto freq = frequencies_[Feature2Idx(feature)];
    if (freq == 0) {
      ++number_of_unseen_features;
    }
    if (freq < FrequencyThreshold(feature)) {
      features[num_kept++] = feature;
    }
  }
  features.resize(num_kept);
  return number_of_unseen_features;
}

void FeatureSet::IncrementFrequencies(const FeatureVec &features) {
  for (auto f : features) {
    auto &freq = frequencies_[Feature2Idx(f)];
    if (freq == 0) {
      ++num_features_;
      ++features_per_domain_[feature_domains::Domain::FeatureToDomainId(f)];
      if (feature_domains::kPCs.Contains(f))
        pc_index_set_.insert(ConvertPCFeatureToPcIndex(f));
    }
    if (freq < FrequencyThreshold(f)) ++freq;
  }
}

__attribute__((noinline))  // to see it in profile.
uint64_t
FeatureSet::ComputeWeight(const FeatureVec &features) const {
  uint64_t weight = 0;
  for (auto feature : features) {
    // The less frequent is the feature, the more valuable it is.
    // (frequency == 1) => (weight == 256)
    // (frequency == 2) => (weight == 128)
    // and so on.
    // The less frequent is the domain, the more valuable are its features.
    auto domain_id = feature_domains::Domain::FeatureToDomainId(feature);
    auto features_in_domain = features_per_domain_[domain_id];
    // features_in_domain may be 0. This is an unfortunate consequence of
    // having a table with collisions. `feature` may have collided with another
    // feature that was from a different domain, and thus didn't increment
    // the right features_per_domain_.
    // TODO(kcc): this class needs a major facelift.
    // Perhaps even rewriting to not have collisions.
    auto domain_weight =
        features_in_domain ? num_features_ / features_in_domain : 1;
    auto feature_idx = Feature2Idx(feature);
    auto feature_frequency = frequencies_[feature_idx];
    CHECK_GT(feature_frequency, 0)
        << VV(feature) << VV(domain_id) << VV(features_in_domain)
        << VV(domain_weight) << VV(feature_idx) << VV((int)feature_frequency)
        << DebugString();
    weight += domain_weight * (256 / feature_frequency);
  }
  return weight;
}

std::string FeatureSet::DebugString() const {
  std::ostringstream os;
  os << VV((int)frequency_threshold_);
  os << VV(num_features_);
  for (size_t domain = 0; domain < feature_domains::kLastDomainId.domain_id();
       ++domain) {
    if (features_per_domain_[domain] == 0) continue;
    os << " dom" << domain << ": " << features_per_domain_[domain];
  }
  return os.str();
}

}  // namespace centipede
