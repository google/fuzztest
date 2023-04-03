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

#ifndef THIRD_PARTY_CENTIPEDE_PAGEMAP_H_
#define THIRD_PARTY_CENTIPEDE_PAGEMAP_H_

#include <cstdint>
#include <functional>
#include <vector>

#include "absl/types/span.h"
#include "./centipede/defs.h"

namespace centipede {

// PageMap knows which pages in the given range of addresses are zero
// and allows to iterate over only non-zero pages.
// Thread-compatible, expected to be used only in one thread.
class PageMap {
 public:
  // Constructs a page map for the range of bytes represented by `range`.
  // `range` does not have to be page-aligned.
  // After the object is constructed it assumes all pages are non-zero.
  PageMap(absl::Span<uint8_t> range);

  // Refreshes the page map, returns true iff successful.
  // Call every time before iterating over pages.
  bool RefreshPageMap();

  // Calls `callback` for every page in the address range provided in CTOR
  // except for the pages that are known to be zero.
  // `offset` is the offset of the page from the beginning of the range.
  void ForEachNonZeroRegion(
      const std::function<void(size_t offset, absl::Span<uint8_t>)> &callback)
      const;

 private:
  FRIEND_TEST(PageMap, ForEachNonZeroRegion);
  FRIEND_TEST(PageMap, RefreshPageMap);

  uint8_t *PageBegin() const;  // First page of the range.
  uint8_t *PageEnd() const;    // Last page of the range.
  // Number of pages in the range.
  size_t SizeInPages() const { return (PageEnd() - PageBegin()) / page_size_; }
  // Index of the page to which `address` belongs.
  size_t PageIndex(const uint8_t *address) const {
    return (address - PageBegin()) / page_size_;
  }

  // Size of the page in bytes.
  uintptr_t page_size_;
  // The address range.
  absl::Span<uint8_t> range_;
  // page_is_known_zero_[i]==true if the i-th page of the range is zero.
  std::vector<bool> page_is_known_zero_;
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_PAGEMAP_H_
