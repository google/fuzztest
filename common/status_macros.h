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

// Convenience macros for dealing with absl::Status and friends.

#ifndef FUZZTEST_COMMON_STATUS_MACROS_H_
#define FUZZTEST_COMMON_STATUS_MACROS_H_

#include <cstdint>

#include "absl/base/attributes.h"
#include "absl/base/optimization.h"
#include "./common/fuzztest_status_macros.h"
#include "./common/logging.h"

#define RETURN_IF_NOT_OK(status_expr) FUZZTEST_RETURN_IF_NOT_OK(status_expr)

#define ASSIGN_OR_RETURN_IF_NOT_OK(dest, src) \
  FUZZTEST_ASSIGN_OR_RETURN_IF_NOT_OK(dest, src)

namespace fuzztest::internal {
template <typename T>
decltype(auto) ValueOrDie(T&& value ABSL_ATTRIBUTE_LIFETIME_BOUND,
                          std::uint_least32_t line = __builtin_LINE(),
                          const char* file_name = __builtin_FILE()) {
  if (ABSL_PREDICT_FALSE(!value.ok())) {
    FUZZTEST_LOG(FATAL) << file_name << ":" << line
                        << ": ValueOrDie on non-OK status: " << value.status();
  }
  return *std::forward<T>(value);
}
}  // namespace fuzztest::internal

#endif  // FUZZTEST_COMMON_STATUS_MACROS_H_
