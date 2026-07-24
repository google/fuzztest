// Copyright 2026 Google LLC
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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_TRAVERSAL_CONTEXT_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_TRAVERSAL_CONTEXT_H_

#include <limits>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "./common/logging.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::domain_implementor {

struct TraversalState {
  // The maximum node depth during domain initialization and mutation.
  int depth_budget = 100;
  // The maximum number of added nodes during domain initialization.
  int init_budget = 1000;
  absl::Status status = absl::OkStatus();
  std::vector<std::string> error_trace;
};

template <typename DomainType>
class TraversalContext {
 public:
  struct PassthroughTag {};
  TraversalContext(TraversalState& state, PassthroughTag) : state_{state} {}

  explicit TraversalContext(TraversalState& state) : state_{state} { Enter(); }

  template <typename OtherDomain>
  TraversalContext(const TraversalContext<OtherDomain>& other)
      : state_{other.state()} {
    Enter();
  }

  TraversalContext(const TraversalContext& other) : state_{other.state_} {
    Enter();
  }

  ~TraversalContext() { Exit(); }

  bool IsResourceExhausted() const {
    return state_.depth_budget < 0 || state_.init_budget < 0;
  }

  bool IsFailed() const { return !state_.status.ok(); }

  void FailWithBudgetExceeded() {
    if (state_.status.ok()) {
      state_.status = absl::ResourceExhaustedError(
          absl::StrFormat("Traversal budget exceeded at %s",
                          fuzztest::internal::GetTypeName<DomainType>()));
    }
  }

  TraversalState& state() const { return state_; }
  absl::Status status() const { return state_.status; }

 protected:
  void Enter() {
    entered_ = true;
    enter_ok_ = state_.status.ok();
    FUZZTEST_CHECK_GT(state_.depth_budget, std::numeric_limits<int>::min());
    state_.depth_budget--;
  }

  void Exit() {
    if (entered_) {
      state_.depth_budget++;
    }
    if (enter_ok_ && !state_.status.ok()) {
      state_.error_trace.push_back(
          std::string(fuzztest::internal::GetTypeName<DomainType>()));
    }
  }

  TraversalState& state_;
  bool enter_ok_ = false;
  bool entered_ = false;
};

template <typename DomainType>
class InitTraversalContext : public TraversalContext<DomainType> {
 public:
  using PassthroughTag =
      typename InitTraversalContext::TraversalContext::PassthroughTag;
  using InitTraversalContext::TraversalContext::TraversalContext;

  template <typename OtherDomain>
  static InitTraversalContext Passthrough(
      const InitTraversalContext<OtherDomain>& other) {
    return InitTraversalContext(other.state(), PassthroughTag{});
  }

  template <typename OtherDomain>
  static InitTraversalContext Passthrough(
      const TraversalContext<OtherDomain>& other) {
    return InitTraversalContext(other.state(), PassthroughTag{});
  }

  explicit InitTraversalContext(TraversalState& state)
      : TraversalContext<DomainType>{state} {
    Decrement();
  }

  template <typename OtherDomain>
  InitTraversalContext(const InitTraversalContext<OtherDomain>& other)
      : TraversalContext<DomainType>{other} {
    Decrement();
  }

  template <typename OtherDomain>
  InitTraversalContext(const TraversalContext<OtherDomain>& other)
      : TraversalContext<DomainType>{other} {
    Decrement();
  }

  InitTraversalContext(const InitTraversalContext& other)
      : TraversalContext<DomainType>{other} {
    Decrement();
  }

 private:
  void Decrement() {
    if (this->state_.init_budget >= 0) {
      --this->state_.init_budget;
    }
  }
};

}  // namespace fuzztest::domain_implementor

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_TRAVERSAL_CONTEXT_H_
