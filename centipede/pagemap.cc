// Copyright 2023 The Centipede Authors.
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

#include "./centipede/pagemap.h"

#include <fcntl.h>
#include <unistd.h>

#include <cstdint>
#include <vector>

#include "absl/types/span.h"

namespace centipede {

static uint8_t *AlignUp(uint8_t *ptr, uintptr_t alignment) {
  auto up =
      (reinterpret_cast<uintptr_t>(ptr) + alignment - 1) & ~(alignment - 1);
  return reinterpret_cast<uint8_t *>(up);
}

static uint8_t *AlignDown(uint8_t *ptr, uintptr_t alignment) {
  auto down = (reinterpret_cast<uintptr_t>(ptr)) & ~(alignment - 1);
  return reinterpret_cast<uint8_t *>(down);
}

PageMap::PageMap(absl::Span<uint8_t> range)
    : page_size_(getpagesize()),
      range_(range),
      page_is_known_zero_(SizeInPages()) {}

uint8_t *PageMap::PageBegin() const {
  return AlignDown(range_.begin(), page_size_);
}

uint8_t *PageMap::PageEnd() const { return AlignUp(range_.end(), page_size_); }

// See `man procmap` for explanation of /proc/self/pagemap.
bool PageMap::RefreshPageMap() {
  using entry_t = uint64_t;
  // read /proc/self/pagemap.
  int pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
  if (pagemap_fd == -1) return false;
  std::vector<entry_t> pagemap(SizeInPages());
  size_t size_to_read = SizeInPages() * sizeof(entry_t);
  size_t size_to_skip =
      reinterpret_cast<uintptr_t>(PageBegin()) / page_size_ * sizeof(entry_t);
  lseek(pagemap_fd, size_to_skip, SEEK_SET);
  int read_res = read(pagemap_fd, pagemap.data(), size_to_read);
  close(pagemap_fd);
  if (read_res != size_to_read) return false;

  // fill page_is_known_zero_.
  for (size_t i = 0, n = SizeInPages(); i < n; ++i) {
    page_is_known_zero_[i] = (pagemap[i] >> 63) == 0;
  }
  return true;
}

void PageMap::ForEachNonZeroRegion(
    const std::function<void(size_t offset, absl::Span<uint8_t>)> &callback)
    const {
  auto *beg = range_.begin();
  auto *end = range_.end();
  auto *end_first_page = AlignUp(beg, page_size_);
  auto *beg_last_page = AlignDown(end, page_size_);
  if (end <= end_first_page) {
    // The region fits in one page - iterate over all of it.
    if (!page_is_known_zero_[PageIndex(beg)])
      callback(0, {beg, static_cast<size_t>(end - beg)});
    return;
  }
  if (beg < end_first_page) {
    // Iterate over the first part, up to the page boundary.
    if (!page_is_known_zero_[PageIndex(beg)])
      callback(0, {beg, static_cast<size_t>(end_first_page - beg)});
  }
  // Iterate over all remaining pages except maybe the last one.
  size_t page_idx = PageIndex(end_first_page);
  for (auto page = end_first_page; page < beg_last_page;
       page += page_size_, ++page_idx) {
    if (!page_is_known_zero_[page_idx])
      callback(page - beg, {page, page_size_});
  }
  if (beg_last_page >= beg && beg_last_page < end) {
    // Iterate over the last part.
    if (!page_is_known_zero_[PageIndex(beg_last_page)])
      callback(beg_last_page - beg,
               {beg_last_page, static_cast<size_t>(end - beg_last_page)});
  }
}

}  // namespace centipede
