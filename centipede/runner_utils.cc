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

#include "./centipede/runner_utils.h"

#include <pthread.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>

#include "absl/base/nullability.h"

namespace fuzztest::internal {

// Weak dummy definition of LSan interface in case LSan is missing.
__attribute__((weak)) void __lsan_register_root_region(const void* p,
                                                       size_t size) {}
__attribute__((weak)) void __lsan_unregister_root_region(const void* p,
                                                         size_t size) {}

void PrintErrorAndExitIf(bool condition, const char* absl_nonnull error) {
  if (!condition) return;
  fprintf(stderr, "error: %s\n", error);
  exit(1);
}

uintptr_t GetCurrentThreadStackRegionLow() {
#ifdef __APPLE__
  pthread_t self = pthread_self();
  const auto stack_addr =
      reinterpret_cast<uintptr_t>(pthread_get_stackaddr_np(self));
  const auto stack_size = pthread_get_stacksize_np(self);
  return stack_addr - stack_size;
#else   // __APPLE__
  pthread_attr_t attr = {};
  if (pthread_getattr_np(pthread_self(), &attr) != 0) {
    fprintf(stderr, "Failed to get the pthread attr of the current thread.\n");
    return 0;
  }
  void *stack_addr = nullptr;
  size_t stack_size = 0;
  if (pthread_attr_getstack(&attr, &stack_addr, &stack_size) != 0) {
    fprintf(stderr, "Failed to get the stack region of the current thread.\n");
    pthread_attr_destroy(&attr);
    return 0;
  }
  pthread_attr_destroy(&attr);
  const auto stack_region_low = reinterpret_cast<uintptr_t>(stack_addr);
  RunnerCheck(stack_region_low != 0,
              "the current thread stack region starts from 0 - unexpected!");
  return stack_region_low;
#endif  // __APPLE__
}

bool ReadAll(int fd, char* data, size_t size) {
  while (size > 0) {
    ssize_t r = read(fd, data, size);
    if (r > 0) {
      // read() guarantees r <= size
      data += r;
      size -= r;
      continue;
    }
    if (r == -1 && errno == EINTR) continue;
    return false;
  }
  return true;
}

bool WriteAll(int fd, const char* data, size_t size) {
  while (size > 0) {
    ssize_t r = write(fd, data, size);
    if (r > 0) {
      // write() guarantees r <= size
      data += r;
      size -= r;
      continue;
    }
    if (r == -1 && errno == EINTR) continue;
    return false;
  }
  return true;
}

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
    : flags_(nullptr), size_(0), has_allocation_failure_(false) {
  if (flags == nullptr) return;
  flags_ = strdup(flags);
  if (flags_ == nullptr) {
    has_allocation_failure_ = true;
    return;
  }
  size_ = ProcessEngineFlags(flags_, strlen(flags_));
}

EngineFlagHelper::~EngineFlagHelper() {
  if (flags_) {
    free(flags_);
  }
}

bool EngineFlagHelper::HasAllocationFailure() const {
  return has_allocation_failure_;
}

bool EngineFlagHelper::HasSwitchFlag(std::string_view flag) const {
  return FindEntry(flag, /*match_whole=*/true) != nullptr;
}

uint64_t EngineFlagHelper::GetIntFlag(std::string_view header,
                                      uint64_t default_value) const {
  const char* absl_nullable flag = GetStringFlag(header);
  if (flag == nullptr) return default_value;
  return atoll(flag);  // NOLINT: can't use strto64, etc.
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
