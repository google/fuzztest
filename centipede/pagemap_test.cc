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

#include <cstdint>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./centipede/defs.h"
#include "./centipede/foreach_nonzero.h"

namespace centipede {

uint8_t small_array[100];     // spans 1-2 pages
uint8_t medium_array[10000];  // spans 3-4 pages.
uint8_t large_array[100000];  // many pages.

TEST(PageMap, ForEachNonZeroRegion) {
  PageMap small_map({small_array, sizeof(small_array)});
  PageMap medium_map({medium_array, sizeof(medium_array)});
  PageMap large_map({large_array, sizeof(large_array)});

  // results of calling ForEachNonZeroRegion().
  std::vector<size_t> res;
  size_t num_nonzero_regions = 0;

  // Call this before ForEachNonZeroRegion().
  auto clear = [&res, &num_nonzero_regions]() {
    res.clear();
    num_nonzero_regions = 0;
  };

  // Callback for ForEachNonZeroRegion().
  auto cb = [&res, &num_nonzero_regions](size_t offset,
                                         absl::Span<uint8_t> span) {
    ++num_nonzero_regions;
    ForEachNonZeroByte(
        span.begin(), span.size(),
        [&](size_t idx, uint8_t byte) { res.push_back(offset + idx); });
  };

  EXPECT_GE(small_map.SizeInPages(), 1);
  EXPECT_LE(small_map.SizeInPages(), 2);

  EXPECT_GE(medium_map.SizeInPages(), 3);
  EXPECT_LE(medium_map.SizeInPages(), 4);

  // test small_map
  clear();
  small_map.ForEachNonZeroRegion(cb);
  EXPECT_THAT(res, testing::ElementsAre());
  EXPECT_LE(num_nonzero_regions, 2);

  small_array[42] = 1;
  small_array[99] = 1;
  clear();
  EXPECT_TRUE(small_map.RefreshPageMap());
  small_map.ForEachNonZeroRegion(cb);
  EXPECT_THAT(res, testing::ElementsAre(42, 99));
  EXPECT_LE(num_nonzero_regions, 2);

  // test medium_map
  medium_array[5000] = 1;
  medium_array[6000] = 1;
  clear();
  EXPECT_TRUE(medium_map.RefreshPageMap());
  medium_map.ForEachNonZeroRegion(cb);
  EXPECT_THAT(res, testing::ElementsAre(5000, 6000));
  EXPECT_LE(num_nonzero_regions, 4);

  // test large_map

  // Gest the number of known zero pages in large_map.
  auto num_zero_pages = [&large_map]() {
    return std::count(large_map.page_is_known_zero_.begin(),
                      large_map.page_is_known_zero_.end(), true);
  };

  // Prints the private pagemap as a string of 0s and 1s.
  auto print_page_map = [](const PageMap& page_map) {
    fprintf(stderr, "pagemap: ");
    for (const auto& byte : page_map.page_is_known_zero_) {
      fprintf(stderr, "%d", byte ? 1 : 0);
    }
    fprintf(stderr, "\n");
  };

  EXPECT_EQ(num_zero_pages(), 0);
  EXPECT_TRUE(large_map.RefreshPageMap());

  const size_t num_zero_pages_before = num_zero_pages();
  EXPECT_GE(num_zero_pages_before, 20);
  clear();
  large_map.ForEachNonZeroRegion(cb);
  EXPECT_THAT(res, testing::ElementsAre());
  EXPECT_LE(num_nonzero_regions, 2);

  // Set two elements of the large_array to non-zero, observe them.
  large_array[70000] = 1;
  large_array[80000] = 1;
  EXPECT_TRUE(large_map.RefreshPageMap());
  EXPECT_EQ(num_zero_pages(), num_zero_pages_before - 2);
  clear();
  large_map.ForEachNonZeroRegion(cb);
  EXPECT_THAT(res, testing::ElementsAre(70000, 80000));
  EXPECT_LE(num_nonzero_regions, 4);

  // Set same two elements and two more elements to non-zero, observe them.
  large_array[50000] = 1;
  large_array[60000] = 1;
  large_array[70000] = 1;
  large_array[80000] = 1;
  EXPECT_TRUE(large_map.RefreshPageMap());
  EXPECT_EQ(num_zero_pages(), num_zero_pages_before - 4);
  print_page_map(large_map);
  clear();
  large_map.ForEachNonZeroRegion(cb);
  print_page_map(large_map);
  EXPECT_THAT(res, testing::ElementsAre(50000, 60000, 70000, 80000));
  EXPECT_LE(num_nonzero_regions, 6);

  // Test various sizes, don't call RefreshPageMap().
  for (size_t size : {1, 2, 3, 4, 20, 40, 50, 60, 70, 80, 90, 100, 1000, 2000,
                      5000, 50000, 500000, 5000000}) {
    std::vector<uint8_t> vec(size);
    // LOG(INFO) << "size: " << size << " vec: " << (void*)vec.data() << "\n";
    vec.front() = 1;
    vec[size / 2] = 2;
    vec.back() = 3;
    PageMap map({vec.data(), size});
    clear();
    map.ForEachNonZeroRegion(cb);
    if (size == 1)
      EXPECT_THAT(res, testing::ElementsAre(0));
    else if (size == 2)
      EXPECT_THAT(res, testing::ElementsAre(0, 1));
    else
      EXPECT_THAT(res, testing::ElementsAre(0, size / 2, size - 1));
  }
}

static constexpr size_t kStressArraySize = 1 << 22;  // 4Mb.
static uint8_t stress_array[kStressArraySize];

// Stress test for RefreshPageMap.
TEST(PageMap, RefreshPageMap) {
  PageMap map({stress_array, kStressArraySize});
  for (size_t iter = 0; iter < 10000; ++iter) {
    map.RefreshPageMap();
    EXPECT_TRUE(map.page_is_known_zero_[42]);
  }
}

}  // namespace centipede
