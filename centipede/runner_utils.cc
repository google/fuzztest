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

#if !defined(_WIN32)
#include <pthread.h>
#include <unistd.h>
#else
#define WIN32_LEAN_AND_MEAN
#define NOGDI
#include <io.h>
#include <process.h>
#include <windows.h>
#include <winsock2.h>
#endif

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

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
#if defined(_WIN32)
  MEMORY_BASIC_INFORMATION mbi = {};
  if (VirtualQuery(&mbi, &mbi, sizeof(mbi)) != 0) {
    return reinterpret_cast<uintptr_t>(mbi.AllocationBase);
  }
  return 0;
#elif defined(__APPLE__)
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
#endif
}

bool ReadAll(intptr_t fd, char* data, size_t size) {
  while (size > 0) {
#if defined(_WIN32)
    int r = recv(static_cast<SOCKET>(fd), data, static_cast<int>(size), 0);
    if (r <= 0 && WSAGetLastError() != 0) {
      r = _read(static_cast<int>(fd), data, static_cast<unsigned int>(size));
    }
#else
    ssize_t r = read(fd, data, size);
#endif
    if (r > 0) {
      data += r;
      size -= r;
      continue;
    }
#if defined(_WIN32)
    if (r == -1 && (WSAGetLastError() == WSAEINTR || errno == EINTR)) continue;
#else
    if (r == -1 && errno == EINTR) continue;
#endif
    return false;
  }
  return true;
}

bool WriteAll(intptr_t fd, const char* data, size_t size) {
  while (size > 0) {
#if defined(_WIN32)
    int r = send(static_cast<SOCKET>(fd), data, static_cast<int>(size), 0);
    if (r <= 0 && WSAGetLastError() != 0) {
      r = _write(static_cast<int>(fd), data, static_cast<unsigned int>(size));
    }
#else
    ssize_t r = write(fd, data, size);
#endif
    if (r > 0) {
      data += r;
      size -= r;
      continue;
    }
#if defined(_WIN32)
    if (r == -1 && (WSAGetLastError() == WSAEINTR || errno == EINTR)) continue;
#else
    if (r == -1 && errno == EINTR) continue;
#endif
    return false;
  }
  return true;
}

}  // namespace fuzztest::internal
