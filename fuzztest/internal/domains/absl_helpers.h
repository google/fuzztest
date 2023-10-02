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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ABSL_HELPERS_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ABSL_HELPERS_H_

#include <cstdint>
#include <limits>
#include <string>
#include <utility>

#include "absl/strings/cord.h"
#include "absl/time/time.h"
#include "./fuzztest/internal/logging.h"

namespace fuzztest::internal {

// This implementation is partially based on knowledge of the current
// implementation of absl::Cord, but does not directly use this representation.
// It will sometimes generate a Cord that directly contains bytes, and sometimes
// generate a Cord that contains an internal tree structure. This implementation
// will not create all possible Cords, but hopefully represents enough to
// discover issue.
inline absl::Cord MakeCord(std::string str, std::string append_str,
                           size_t target_size, bool set_checksum) {
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(
      append_str.size() >= 512U,
      "Append string should be at least 512 bytes long to ensure Cord "
      "generates a tree");

  if (str.empty() || target_size <= str.size()) return absl::Cord(str);

  std::string* mem = new std::string(append_str);
  absl::Cord append = absl::MakeCordFromExternal(
      *mem, [mem](absl::string_view) { delete mem; });

  // If we need a huge cord, a small append string won't be large enough to grow
  // the tree quickly enough, and we'll spend an enormous amount of time
  // balancing the tree. In that case, create a large append string that's only
  // a little smaller than the target size.
  std::string large_append_str = append_str;
  while (large_append_str.size() < target_size / (256 * 1024)) {
    large_append_str += large_append_str;
  }
  std::string* large_mem = new std::string(large_append_str);
  absl::Cord large_append = absl::MakeCordFromExternal(
      *large_mem, [large_mem](absl::string_view) { delete large_mem; });

  auto c = absl::Cord(str);
  while (c.size() < target_size) {
    c.Prepend(append);
    c.Append(c);
    c.Append(append);
    c.Append(large_append);
    if (set_checksum) c.SetExpectedChecksum(1);
  }
  FUZZTEST_INTERNAL_CHECK(c.size() >= target_size,
                          "Length of generated Cord smaller than expected");
  return c;
}

// Note: this implementation is based on knowledge of internal
// representation of absl::Duration and will not cover all
// possible arbitrary durations if the internal representation
// changes.
inline absl::Duration MakeDuration(int64_t secs, uint32_t ticks) {
  // The granularity of a duration is as small as a quarter of a
  // nanosecond.
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(ticks >= 0u && ticks <= 3'999'999'999u,
                                       "Ticks should be in range [0, 4B - 1]!");
  return absl::Seconds(secs) + (absl::Nanoseconds(1) / 4) * ticks;
}

// Note: duration `d` needs to be finite.
inline std::pair<int64_t, uint32_t> GetSecondsAndTicks(absl::Duration d) {
  absl::Duration rem;
  int64_t secs = absl::IDivDuration(d, absl::Seconds(1), &rem);
  int64_t ticks = (4 * rem) / absl::Nanoseconds(1);
  if (ticks < 0) {
    // It is impossible to have both a negative remainder and int64min seconds.
    FUZZTEST_INTERNAL_CHECK(secs != std::numeric_limits<int64_t>::min(),
                            "Seconds should not be int64 min!");
    secs -= 1;
    ticks += 4'000'000'000;
  }
  FUZZTEST_INTERNAL_CHECK(0 <= ticks && ticks < 4'000'000'000,
                          "Ticks should be in range [0, 4B - 1]!");
  return {secs, static_cast<uint32_t>(ticks)};
}

// Note: duration `d` needs to be finite.
inline int64_t GetSeconds(absl::Duration d) {
  return GetSecondsAndTicks(d).first;
}

// Note: duration `d` needs to be finite.
inline uint32_t GetTicks(absl::Duration d) {
  return GetSecondsAndTicks(d).second;
}

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ABSL_HELPERS_H_
