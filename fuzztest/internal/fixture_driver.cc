// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./fuzztest/internal/fixture_driver.h"

namespace fuzztest::internal {

UntypedFixtureDriver::UntypedFixtureDriver(
    std::unique_ptr<UntypedDomainInterface> domain,
    std::vector<GenericDomainCorpusType> seeds)
    : domain_(std::move(domain)), seeds_(std::move(seeds)) {}
UntypedFixtureDriver::~UntypedFixtureDriver() = default;
void UntypedFixtureDriver::SetUpFuzzTest() {}
void UntypedFixtureDriver::SetUpIteration() {}
void UntypedFixtureDriver::TearDownIteration() {}
void UntypedFixtureDriver::TearDownFuzzTest() {}
std::vector<GenericDomainCorpusType> GetDynamicSeeds() { return {}; }

std::vector<GenericDomainCorpusType> UntypedFixtureDriver::GetSeeds() const {
  return seeds_;
}
std::vector<GenericDomainCorpusType> UntypedFixtureDriver::GetDynamicSeeds() {
  return {};
}

std::unique_ptr<UntypedDomainInterface> UntypedFixtureDriver::GetDomains()
    const {
  return domain_->Clone();
}

}  // namespace fuzztest::internal
