// Copyright 2026 The FuzzTest Authors.
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

#ifndef FUZZTEST_COMMON_FUZZTEST_STATUS_MACROS_H_
#define FUZZTEST_COMMON_FUZZTEST_STATUS_MACROS_H_

#include "absl/base/optimization.h"

// If `status_expr` (an expression of type `absl::Status`) is not OK then return
// it from the current function. Otherwise, do nothing.
#define FUZZTEST_RETURN_IF_NOT_OK(status_expr)       \
  do {                                               \
    const absl::Status status_value = (status_expr); \
    if (ABSL_PREDICT_FALSE(!status_value.ok())) {    \
      return status_value;                           \
    }                                                \
  } while (false)

// Internal helpers for concatenating macro values.
#define FUZZTEST_STATUS_MACROS_IMPL_CONCAT_IMPL_(x, y) x##y
#define FUZZTEST_STATUS_MACROS_IMPL_CONCAT_(x, y) \
  FUZZTEST_STATUS_MACROS_IMPL_CONCAT_IMPL_(x, y)

// Assigns `dest` to the value contained within the `absl::StatusOr<T> src` if
// `src.ok()`, otherwise, returns `src.status()` from the current function.
#define FUZZTEST_ASSIGN_OR_RETURN_IF_NOT_OK(dest, src) \
  FUZZTEST_ASSIGN_OR_RETURN_IF_NOT_OK_IMPL_(           \
      FUZZTEST_STATUS_MACROS_IMPL_CONCAT_(value_or_, __LINE__), dest, src)

#define FUZZTEST_ASSIGN_OR_RETURN_IF_NOT_OK_IMPL_(value_or, dest, src) \
  auto value_or = (src);                                               \
  if (ABSL_PREDICT_FALSE(!value_or.ok())) {                            \
    return std::move(value_or).status();                               \
  }                                                                    \
  dest = std::move(value_or).value()

#endif  // FUZZTEST_COMMON_FUZZTEST_STATUS_MACROS_H_
