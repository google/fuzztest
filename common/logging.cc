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

#include "./common/logging.h"

#ifdef _WIN32
#include <algorithm>
#include <cstdio>
#include <limits>

#include "./common/windows_includes.h"
#else
#include <unistd.h>
#endif

#include <cerrno>
#include <cstddef>

#include "absl/strings/string_view.h"

namespace fuzztest::internal {

void WriteSignalSafeStderr(absl::string_view sv) {
  const int saved_errno = errno;
#ifdef _WIN32
  const int fd = _fileno(stderr);
  if (fd >= 0) {
    while (!sv.empty()) {
      const unsigned int chunk = static_cast<unsigned int>(
          std::min<size_t>(sv.size(), std::numeric_limits<int>::max()));
      const int r = _write(fd, sv.data(), chunk);
      if (r > 0) {
        sv.remove_prefix(static_cast<size_t>(r));
        continue;
      }
      if (r == -1 && errno == EINTR) continue;
      break;
    }
  }
#else
  while (!sv.empty()) {
    const ssize_t r = write(STDERR_FILENO, sv.data(), sv.size());
    if (r > 0) {
      sv.remove_prefix(static_cast<size_t>(r));
      continue;
    }
    if (r == -1 && errno == EINTR) continue;
    break;
  }
#endif
  errno = saved_errno;
}

void SyncSignalSafeStderr() {
#ifndef _WIN32
  const int saved_errno = errno;
  (void)fsync(STDERR_FILENO);
  errno = saved_errno;
#endif
}

}  // namespace fuzztest::internal
