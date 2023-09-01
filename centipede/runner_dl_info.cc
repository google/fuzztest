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

#include "./centipede/runner_dl_info.h"

#include <elf.h>
#include <link.h>  // dl_iterate_phdr
#include <unistd.h>

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "./centipede/runner_utils.h"

namespace centipede {

namespace {

// Struct to pass to dl_iterate_phdr's callback.
struct DlCallbackParam {
  // Full path to the instrumented library or nullptr for the main binary.
  const char *dl_path_suffix;
  // PC to look for in a DL.
  uintptr_t pc;
  // DlInfo to set on success.
  DlInfo &result;
};

bool StringEndsWithSuffix(const char *string, const char *suffix) {
  const char *pos = strstr(string, suffix);
  if (pos == nullptr) return false;
  return pos == string + strlen(string) - strlen(suffix);
}

int g_some_global;  // Used in DlIteratePhdrCallback.

constexpr bool kDlDebug = false;  // we may want to make it a runtime flag.

// Returns the size of the DL represented by `info`.
size_t DlSize(struct dl_phdr_info *info) {
  size_t size = 0;
  // Iterate program headers.
  for (int j = 0; j < info->dlpi_phnum; ++j) {
    // We are only interested in "Loadable program segments".
    const auto &phdr = info->dlpi_phdr[j];
    if (phdr.p_type != PT_LOAD) continue;
    // phdr.p_vaddr represents the offset of the segment from info->dlpi_addr.
    // phdr.p_memsz is the segment size in bytes.
    // Their sum is the offset of the end of the segment from info->dlpi_addr.
    uintptr_t end_offset = phdr.p_vaddr + phdr.p_memsz;
    // We compute result.size as the largest such offset.
    if (size < end_offset) size = end_offset;

    // phdr.p_flags indicates RWX access rights for the segment,
    // e.g. `phdr.p_flags & PF_X` is non-zero if the segment is executable.
    if constexpr (kDlDebug) {
      char executable_bit = (phdr.p_flags & PF_X) ? 'X' : '-';
      char writable_bit = (phdr.p_flags & PF_W) ? 'W' : '-';
      char readable_bit = (phdr.p_flags & PF_R) ? 'R' : '-';
      fprintf(stderr,
              "%s: segment [%d] name: %s addr: %" PRIx64 " size: %" PRIu64
              " flags: %c%c%c\n",
              __func__, j, info->dlpi_name, phdr.p_vaddr, phdr.p_memsz,
              executable_bit, writable_bit, readable_bit);
    }
  }
  return size;
}

// See man dl_iterate_phdr.
// `param_voidptr` is cast to a `DlCallbackParam *param`.
// Looks for the dynamic library who's dlpi_name ends with
// `param->dl_path_suffix` or for the main binary if `param->dl_path_suffix ==
// nullptr`. The code assumes that the main binary is the first one to be
// iterated on. If the desired library is found, sets result.start_address and
// result.size, otherwise leaves result unchanged.
int DlIteratePhdrCallback(struct dl_phdr_info *info, size_t size,
                          void *param_voidptr) {
  const DlCallbackParam *param = static_cast<DlCallbackParam *>(param_voidptr);
  DlInfo &result = param->result;
  RunnerCheck(!result.IsSet(), "result is already set");
  // Skip uninteresting info.
  if (param->dl_path_suffix != nullptr &&
      !StringEndsWithSuffix(info->dlpi_name, param->dl_path_suffix)) {
    return 0;  // 0 indicates we want to see the other entries.
  }

  const auto some_code_address =
      reinterpret_cast<uintptr_t>(DlIteratePhdrCallback);
  const auto some_global_address = reinterpret_cast<uintptr_t>(&g_some_global);

  result.start_address = info->dlpi_addr;
  result.size = DlSize(info);
  // copy dlpi_name to result.path.
  strncpy(result.path, info->dlpi_name, sizeof(result.path));
  result.path[sizeof(result.path) - 1] = 0;

  if constexpr (kDlDebug) {
    fprintf(stderr,
            "%s: name: %s addr: %" PRIx64 " size: %" PRIu64
            " addr+size: %" PRIx64 " code: %" PRIx64 " global: %" PRIx64 "\n",
            __func__, info->dlpi_name, info->dlpi_addr, result.size,
            info->dlpi_addr + result.size, some_code_address,
            some_global_address);
  }

  RunnerCheck(result.size != 0,
              "DlIteratePhdrCallback failed to compute result.size");
  if (param->dl_path_suffix == nullptr) {
    // When the main binary is coverage-instrumented, we currently only support
    // statically linking this runner. Which means, that the runner itself
    // is part of the main binary, and we can do additional checks, which we
    // can't do if the runner is a separate library.
    RunnerCheck(result.InBounds(some_code_address),
                "DlIteratePhdrCallback: a sample code address is not in bounds "
                "of main executable");
    RunnerCheck(result.InBounds(some_global_address),
                "DlIteratePhdrCallback: a sample global address is not in "
                "bounds of main executable");
  }
  return result.IsSet();  // return 1 if we found what we were looking for.
}

// See man dl_iterate_phdr.
// `param_voidptr` is cast to a `DlCallbackParam *param`.
// Looks for the dynamic library who's address range contains `param->pc`.
int DlIteratePhdrPCCallback(struct dl_phdr_info *info, size_t unused,
                            void *param_voidptr) {
  const DlCallbackParam *param = static_cast<DlCallbackParam *>(param_voidptr);
  DlInfo &result = param->result;
  if (param->pc < info->dlpi_addr) return 0;  // wrong DSO.
  const size_t size = DlSize(info);
  if (param->pc >= info->dlpi_addr + size) return 0;  // wrong DSO.
  result.start_address = info->dlpi_addr;
  result.size = size;
  if (strlen(info->dlpi_name) != 0) {
    // copy dlpi_name to result.path.
    strncpy(result.path, info->dlpi_name, sizeof(result.path));
  } else {
    // dlpi_name is empty, this is the main binary, get path via /proc/self/exe.
    int res = readlink("/proc/self/exe", result.path, sizeof(result.path));
    RunnerCheck(res > 0, "readlink(\"/proc/self/exe\") failed");
  }
  result.path[sizeof(result.path) - 1] = 0;
  return 0;  // Found what we are looking for.
}

}  // namespace

DlInfo GetDlInfo(const char *dl_path_suffix) {
  DlInfo result;
  result.Clear();
  DlCallbackParam callback_param = {dl_path_suffix, /*pc=*/0, result};
  dl_iterate_phdr(DlIteratePhdrCallback, &callback_param);
  return result;
}

DlInfo GetDlInfo(uintptr_t pc) {
  DlInfo result;
  result.Clear();
  DlCallbackParam callback_param = {/*dl_path_suffix=*/nullptr, pc, result};
  dl_iterate_phdr(DlIteratePhdrPCCallback, &callback_param);
  return result;
}

}  // namespace centipede
