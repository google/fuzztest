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

#ifndef FUZZTEST_CENTIPEDE_COVERAGE_SYMBOLIZER_H_
#define FUZZTEST_CENTIPEDE_COVERAGE_SYMBOLIZER_H_

#include <stddef.h>

#include <functional>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "./centipede/feature.h"
#include "./centipede/symbol_table.h"

namespace centipede {

// Provides symbols for one type of coverage features in a domain.
// Note: Not thread-safe.
class DomainSymbolizer {
 public:
  // Instantiates a DomainSymbolizer for Domain with `domain_id`.
  explicit DomainSymbolizer(size_t domain_id);

  // Returns a pointer to a symbol table that can be populated with entries for
  // coverage features.
  absl::StatusOr<SymbolTable *> InitializeByPopulatingSymbolTable();
  // Registers a function to be used for symbolizing coverage features.
  // Given an index into the domain, the function should return the description
  // of the feature at that index.
  absl::Status InitializeWithSymbolizationFunction(
      const std::function<std::string(size_t idx)> &func);

  // Returns a description of the feature at the provided index in the domain.
  // If the symbolizer is uninitialized, returns an "unknown feature" message.
  std::string GetSymbolForIndex(size_t idx) const;

 private:
  // Holds symbols for coverage features. Unpopulated if initialized with
  // symbolization function.
  SymbolTable symbols_;
  // Function that symbolizes the feature at the provided index `idx`. If
  // initialized by populating `symbols_`, looks up the relevant symbol in
  // `symbols_`.
  std::function<std::string(size_t idx)> func_;
  // Domain ID of the domain this object symbolizes.
  size_t domain_id_;
  // Ensures that we cannot be initialized more than once.
  bool initialized_;
};

// Provides symbols for features in any domain.
// Note: Not thread-safe.
class CoverageSymbolizer {
 public:
  CoverageSymbolizer();

  // Returns pointer to corresponding symbolizer for `domain`.
  absl::StatusOr<DomainSymbolizer *> GetSymbolizerForDomain(
      feature_domains::Domain domain);

  // Returns the symbol for `feature`. The symbol will be "unknown feature" for
  // uninitialized domain symbolizers.
  std::string GetSymbolForFeature(feature_t feature) const;

 private:
  // Symbolizers for the valid domains.
  std::vector<DomainSymbolizer> symbolizers_;
};

}  // namespace centipede

#endif  // FUZZTEST_CENTIPEDE_COVERAGE_SYMBOLIZER_H_
