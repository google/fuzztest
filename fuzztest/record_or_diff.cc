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

#include "./fuzztest/record_or_diff.h"

#include <string>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/internal/runtime.h"

namespace fuzztest::internal {

void ReportRecordOrDiffDuplicateLabel(absl::string_view label) {
  Runtime::instance().ReportDiffUsageError(
      absl::StrCat("RecordOrDiff label \"", label,
                   "\" used twice in one input; give each call a distinct "
                   "label"),
      "RecordOrDiff usage error: duplicate label");
}

void ReportRecordOrDiffMissingComparator(absl::string_view type_name,
                                         bool is_proto) {
  Runtime::instance().ReportDiffUsageError(
      absl::StrCat(
          "RecordOrDiff: ", type_name,
          " has no operator==; pass RecordOrDiffOptions::comparator",
          is_proto ? " (e.g. google::protobuf::util::MessageDifferencer::Equals)" : ""),
      "RecordOrDiff usage error: missing comparator");
}

void ReportRecordOrDiffSerializationFailure(absl::string_view label) {
  Runtime::instance().ReportDiffUsageError(
      absl::StrCat("RecordOrDiff: cannot serialize the value for label \"",
                   label, "\"; provide a fuzztest::DiffCodec<T>."),
      "RecordOrDiff serialization failure");
}

void ReportRecordOrDiffInvalidCodec(absl::string_view label) {
  Runtime::instance().ReportDiffUsageError(
      absl::StrCat("RecordOrDiff: the fuzztest::DiffCodec<T> for label \"",
                   label, "\" must have both a serializer and a deserializer"),
      "RecordOrDiff usage error: invalid codec");
}

std::string EscapeRecordOrDiffBytes(absl::string_view bytes) {
  return absl::StrCat("\"", absl::CEscape(bytes), "\"");
}

}  // namespace fuzztest::internal
