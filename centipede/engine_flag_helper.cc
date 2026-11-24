// Copyright 2022 The Centipede Authors.
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

#include "./centipede/engine_flag_helper.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>

#include "absl/base/nullability.h"

namespace fuzztest::internal {

size_t ProcessEngineFlags(char* flags, size_t size) {
  size_t r = 0;
  size_t w = 0;
  size_t cur_flag_beg = 0;
  for (r = 0; r < size; ++r) {
    if (flags[r] == ':') {
      if (w > 0 && w == cur_flag_beg) {
        // Skip empty flags
        continue;
      }
      flags[w++] = 0;
      cur_flag_beg = w;
      continue;
    }
    // Skip copying if no flag beg was scanned before.
    if (cur_flag_beg == 0) continue;
    if (flags[r] == '\\' && r + 1 < size) {
      ++r;
    }
    flags[w++] = flags[r];
  }
  if (cur_flag_beg < 2) return 0;
  return cur_flag_beg;
}

EngineFlagHelper::EngineFlagHelper(const char* absl_nullable flags)
    : flags_(nullptr), size_(0) {
  if (flags == nullptr) return;
  flags_ = strdup(flags);
  if (flags_ == nullptr) {
    // This should rarely happen.
    fprintf(stderr, "Failed to copy the flags due to allocation failure.\n");
    std::_Exit(1);
  }
  size_ = ProcessEngineFlags(flags_, strlen(flags_));
}

EngineFlagHelper::~EngineFlagHelper() {
  if (flags_) {
    free(flags_);
  }
}

bool EngineFlagHelper::HasSwitchFlag(std::string_view flag) const {
  return FindEntry(flag, /*match_whole=*/true) != nullptr;
}

uint64_t EngineFlagHelper::GetIntFlag(std::string_view header,
                                      uint64_t default_value) const {
  const char* absl_nullable flag = GetStringFlag(header);
  if (flag == nullptr) return default_value;
  return std::strtoull(flag, nullptr, 10);  // NOLINT(runtime/deprecated_fn)
}

const char* absl_nullable EngineFlagHelper::GetStringFlag(
    std::string_view header) const {
  const char* absl_nullable entry = FindEntry(header);
  if (entry == nullptr) return nullptr;
  return entry + header.size();
}

const char* absl_nullable EngineFlagHelper::FindEntry(std::string_view flag,
                                                      bool match_whole) const {
  if (flags_ == nullptr || flag.empty()) return nullptr;
  auto flags = std::string_view{flags_, size_};
  while (true) {
    auto match = flags.find(flag);
    if (match == flags.npos) return nullptr;
    if ((match > 0 && flags[match - 1] == 0) &&
        (!match_whole || flags[match + flag.size()] == 0)) {
      return flags.data() + match;
    }
    flags = flags.substr(match + flag.size());
  }
}

}  // namespace fuzztest::internal
