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

#include "./centipede/config_util.h"

#include "absl/flags/reflection.h"
#include "absl/strings/match.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/substitute.h"

namespace centipede::config {

FlagInfosPerSource GetFlagsPerSource(
    std::string_view source_prefix,
    const std::set<std::string_view>& exclude_flags) {
  FlagInfosPerSource flags_per_source;
  for (const auto& [name, flag] : absl::GetAllFlags()) {
    if (absl::StartsWith(flag->Filename(), source_prefix) &&
        exclude_flags.find(name) == exclude_flags.cend()) {
      flags_per_source[flag->Filename()].emplace(FlagInfo{
          name, flag->CurrentValue(), flag->DefaultValue(), flag->Help()});
    }
  }
  return flags_per_source;
}

std::string FormatFlagfileString(const FlagInfosPerSource& flags,
                                 DefaultedFlags defaulted,
                                 FlagComments comments) {
  std::vector<std::string> lines;
  lines.reserve(flags.size());  // this many files

  if (defaulted == DefaultedFlags::kIncluded) {
    lines.emplace_back("# NOTE: Explicit and defaulted flags are included");
  } else if (defaulted == DefaultedFlags::kExcluded) {
    lines.emplace_back("# NOTE: Defaulted flags are excluded");
  } else if (defaulted == DefaultedFlags::kCommentedOut) {
    lines.emplace_back("# NOTE: Defaulted flags are commented out");
  }
  lines.emplace_back();

  for (const auto& [filename, flag_infos] : flags) {
    lines.emplace_back(absl::Substitute("# Flags from $0:", filename));
    for (const auto& [name, value, default_value, help] : flag_infos) {
      if (defaulted == DefaultedFlags::kExcluded && value == default_value) {
        continue;
      }
      if (comments == FlagComments::kHelpAndDefault) {
        const std::string prepped_help =
            absl::StrReplaceAll(help, {{"\n", " "}});
        lines.emplace_back(absl::Substitute("  # $0", prepped_help));
      }
      if (comments == FlagComments::kDefault ||
          comments == FlagComments::kHelpAndDefault) {
        lines.emplace_back(
            absl::Substitute("  # default: '$0'", default_value));
      }
      if (defaulted == DefaultedFlags::kCommentedOut &&
          value == default_value) {
        lines.emplace_back(absl::Substitute("  # --$0=$1", name, value));
      } else {
        lines.emplace_back(absl::Substitute("  --$0=$1", name, value));
      }
      if (comments == FlagComments::kDefault ||
          comments == FlagComments::kHelpAndDefault) {
        lines.emplace_back();
      }
    }
    if (!lines.back().empty()) lines.emplace_back();
  }

  return absl::StrJoin(lines, "\n");
}

}  // namespace centipede::config
