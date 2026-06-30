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

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest {
template <typename T>
class Domain;
}

namespace fuzztest::internal {

struct TraversalState {
  int depth = 100;  // Default max depth
  std::optional<int> count;
  absl::Status status = absl::OkStatus();
  std::vector<std::string> error_trace;
};

struct TraversalCheckpoint {
  int depth;
  std::optional<int> count;
  absl::Status status;
  size_t error_trace_size;
};

inline constexpr int kDefaultMaxCount = 1000;

template <typename DomainType>
class TraversalContext {
 public:
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
    return state_.depth < 0 || (state_.count.has_value() && *state_.count < 0);
  }

  bool IsFailed() const { return !state_.status.ok(); }

  void Fail() {
    if (state_.status.ok()) {
      state_.status = absl::ResourceExhaustedError(absl::StrFormat(
          "Traversal budget exceeded at %s", GetTypeName<DomainType>()));
    }
  }

  TraversalCheckpoint Checkpoint() const {
    return {state_.depth, state_.count, state_.status,
            state_.error_trace.size()};
  }

  void Restore(const TraversalCheckpoint& checkpoint) {
    state_.depth = checkpoint.depth;
    state_.count = checkpoint.count;
    state_.status = checkpoint.status;
    state_.error_trace.resize(checkpoint.error_trace_size);
  }

  TraversalState& state() const { return state_; }

 protected:
  void Enter() {
    enter_ok_ = state_.status.ok();
    depth_decremented_ = state_.depth > -1;
    if (depth_decremented_) {
      state_.depth--;
    }
    if (state_.count.has_value()) {
      *state_.count = std::max(-1, *state_.count - 1);
    }
  }

  void Exit() {
    if (depth_decremented_) {
      state_.depth++;
    }
    if (enter_ok_ && !state_.status.ok()) {
      state_.error_trace.push_back(std::string(GetTypeName<DomainType>()));
    }
  }

  TraversalState& state_;
  bool enter_ok_ = false;
  bool depth_decremented_ = false;
};

template <typename DomainType>
class TraversalContextWithTotalCount : public TraversalContext<DomainType> {
 public:
  explicit TraversalContextWithTotalCount(TraversalState& state)
      : TraversalContext<DomainType>{state} {
    InitCount();
  }

  template <typename OtherDomain>
  TraversalContextWithTotalCount(
      const TraversalContextWithTotalCount<OtherDomain>& other)
      : TraversalContext<DomainType>{other} {
    InitCount();
  }

  template <typename OtherDomain>
  TraversalContextWithTotalCount(const TraversalContext<OtherDomain>& other)
      : TraversalContext<DomainType>{other} {
    InitCount();
  }

  TraversalContextWithTotalCount(const TraversalContextWithTotalCount& other)
      : TraversalContext<DomainType>{other} {
    InitCount();
  }

  ~TraversalContextWithTotalCount() {
    if (!enter_has_count_) {
      this->state().count = std::nullopt;
    }
  }

 private:
  void InitCount() {
    enter_has_count_ = this->state().count.has_value();
    if (!enter_has_count_) {
      this->state().count = kDefaultMaxCount - 1;
    }
  }
  bool enter_has_count_ = true;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_TRAVERSAL_CONTEXT_H_
