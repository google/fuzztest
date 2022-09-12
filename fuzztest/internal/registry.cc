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

#include "./fuzztest/internal/registry.h"

#include <deque>
#include <functional>
#include <string>
#include <string_view>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "./fuzztest/internal/registration.h"
#include "./fuzztest/internal/runtime.h"

namespace fuzztest::internal {
namespace {

auto& Regs() {
  // We use a deque because FuzzTest is not copyable/movable.
  static auto* reg = new std::deque<FuzzTest>;
  return *reg;
}

using SetUpTearDownTestSuiteFunctionPair =
    std::pair<SetUpTearDownTestSuiteFunction, SetUpTearDownTestSuiteFunction>;

auto& SetUpTearDownTestSuiteRegistry() {
  static auto* const registry =
      new absl::flat_hash_map<std::string, SetUpTearDownTestSuiteFunctionPair>;
  return *registry;
}

SetUpTearDownTestSuiteFunctionPair GetSetUpTearDownTestSuiteFunctions(
    std::string_view suite_name) {
  if (auto it = SetUpTearDownTestSuiteRegistry().find(std::string(suite_name));
      it != SetUpTearDownTestSuiteRegistry().end()) {
    return it->second;
  }
  return {nullptr, nullptr};
}

}  // namespace

void ForEachTest(const std::function<void(const FuzzTest&)>& func) {
  for (auto& t : Regs()) func(t);
}

void RegisterImpl(BasicTestInfo test_info, FuzzTestFuzzerFactory factory) {
  Regs().emplace_back(test_info, std::move(factory));
}

void RegisterSetUpTearDownTestSuiteFunctions(
    std::string_view suite_name,
    SetUpTearDownTestSuiteFunction set_up_test_suite,
    SetUpTearDownTestSuiteFunction tear_down_test_suite) {
  SetUpTearDownTestSuiteRegistry().try_emplace(
      std::string(suite_name), set_up_test_suite, tear_down_test_suite);
}

SetUpTearDownTestSuiteFunction GetSetUpTestSuite(std::string_view suite_name) {
  return GetSetUpTearDownTestSuiteFunctions(suite_name).first;
}

SetUpTearDownTestSuiteFunction GetTearDownTestSuite(
    std::string_view suite_name) {
  return GetSetUpTearDownTestSuiteFunctions(suite_name).second;
}

}  // namespace fuzztest::internal
