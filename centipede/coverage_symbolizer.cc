// Copyright 2023 The Centipede Authors.
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

#include "./centipede/coverage_symbolizer.h"

#include <stddef.h>

#include <functional>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "./centipede/feature.h"
#include "./centipede/symbol_table.h"

namespace centipede {

DomainSymbolizer::DomainSymbolizer(size_t domain_id)
    : domain_id_(domain_id), initialized_(false) {
  func_ = [domain_id](size_t idx) -> std::string {
    return absl::StrFormat("unknown symbol: domain_id=%d, idx=%d", domain_id,
                           idx);
  };
}

absl::StatusOr<SymbolTable *>
DomainSymbolizer::InitializeByPopulatingSymbolTable() {
  if (initialized_) {
    return absl::FailedPreconditionError(absl::StrCat(
        "Already initialized this domain symbolizer for domain_id=",
        domain_id_));
  }
  initialized_ = true;
  func_ = [this](size_t idx) -> std::string {
    return symbols_.full_description(idx);
  };
  return &symbols_;
}

absl::Status DomainSymbolizer::InitializeWithSymbolizationFunction(
    const std::function<std::string(size_t idx)> &func) {
  if (initialized_) {
    return absl::FailedPreconditionError(absl::StrCat(
        "Already initialized this domain symbolizer for domain_id=",
        domain_id_));
  }
  initialized_ = true;
  func_ = func;
  return absl::OkStatus();
}

std::string DomainSymbolizer::GetSymbolForIndex(size_t idx) const {
  return func_(idx);
}

CoverageSymbolizer::CoverageSymbolizer() {
  for (size_t i = 0; i < feature_domains::kLastDomain.domain_id(); ++i) {
    symbolizers_.emplace_back(/*domain_id=*/i);
  }
}

absl::StatusOr<DomainSymbolizer *> CoverageSymbolizer::GetSymbolizerForDomain(
    feature_domains::Domain domain) {
  if (domain.domain_id() >= feature_domains::kLastDomain.domain_id()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Provided invalid domain_id: ", domain.domain_id()));
  }
  return &symbolizers_[domain.domain_id()];
}

std::string CoverageSymbolizer::GetSymbolForFeature(feature_t feature) const {
  size_t domain_id = feature_domains::Domain::FeatureToDomainId(feature);
  size_t domain_index = feature_domains::Domain::FeatureToDomainIndex(feature);
  return symbolizers_[domain_id].GetSymbolForIndex(domain_index);
}

}  // namespace centipede
