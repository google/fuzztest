// Copyright 2025 Google LLC
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

#include "./fuzztest/internal/fuzzing_bit_gen.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

#include "absl/container/flat_hash_map.h"
#include "absl/debugging/leak_check.h"
#include "absl/types/span.h"
#include "./fuzztest/internal/register_fuzzing_mocks.h"

namespace fuzztest::internal {

FuzzingBitGen::FuzzingBitGen(absl::Span<const uint8_t> data_stream)
    : data_stream_(data_stream) {
  // Seed the internal URBG with the first 8 bytes of the data stream.
  uint64_t stream_seed = 0x6C7FD535EDC7A62D;
  if (!data_stream_.empty()) {
    size_t num_bytes = std::min(sizeof(stream_seed), data_stream_.size());
    std::memcpy(&stream_seed, data_stream_.data(), num_bytes);
    data_stream_.remove_prefix(num_bytes);
  }
  seed(stream_seed);
}

FuzzingBitGen::result_type FuzzingBitGen::operator()() {
  // The non-mockable calls will consume the next 8 bytes from the data
  // stream until it is exhausted, then they will return a value from the
  // internal URBG.
  if (!data_stream_.empty()) {
    result_type x = 0;
    if (data_stream_.size() >= sizeof(x)) {
      std::memcpy(&x, data_stream_.data(), sizeof(x));
      data_stream_.remove_prefix(sizeof(x));
    } else {
      std::memcpy(&x, data_stream_.data(), data_stream_.size());
      data_stream_.remove_prefix(data_stream_.size());
    }
    return x;
  }

  // Fallback to the internal URBG.
  state_ = lcg(state_);
  return mix(state_);
}

bool FuzzingBitGen::InvokeMock(MockIdType key_id, void* args_tuple,
                               void* result) {
  static_assert(
      std::is_same_v<fuzztest::internal::TypeErasedFuzzKeyT, MockIdType>);

  using TypeErasedFuzzFunctionT =
      util_random::internal::TypeErasedFuzzFunctionT;
  using FuzzMapT = absl::flat_hash_map<MockIdType, TypeErasedFuzzFunctionT>;
  static FuzzMapT* fuzzing_map = []() {
    auto* map = absl::IgnoreLeak(new FuzzMapT);
    auto register_fn = [map](auto key, auto fn) { (*map)[key] = fn; };
    fuzztest::internal::RegisterAbslRandomFuzzingMocks(register_fn);
    return map;
  }();

  auto it = fuzzing_map->find(key_id);
  if (it == fuzzing_map->end()) {
    return false;
  }
  it->second(data_stream_, args_tuple, result);
  return true;
}

}  // namespace fuzztest::internal
