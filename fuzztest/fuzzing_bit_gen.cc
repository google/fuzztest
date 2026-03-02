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

#include "./fuzztest/fuzzing_bit_gen.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>

#include "absl/base/fast_type_id.h"
#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/numeric/bits.h"
#include "absl/numeric/int128.h"
#include "absl/types/span.h"
#include "./fuzztest/internal/register_fuzzing_mocks.h"

namespace fuzztest {
namespace {

// Minimal implementation of a PCG64 engine equivalent to xsl_rr_128_64.
inline constexpr absl::uint128 multiplier() {
  return absl::MakeUint128(0x2360ed051fc65da4, 0x4385df649fccf645);
}
inline constexpr absl::uint128 increment() {
  return absl::MakeUint128(0x5851f42d4c957f2d, 0x14057b7ef767814f);
}
inline absl::uint128 lcg(absl::uint128 s) {
  return s * multiplier() + increment();
}
inline uint64_t mix(absl::uint128 state) {
  uint64_t h = absl::Uint128High64(state);
  uint64_t rotate = h >> 58u;
  uint64_t s = absl::Uint128Low64(state) ^ h;
  return absl::rotr(s, rotate);
}

enum class Instruction : uint8_t {
  kDataStreamVariate = 0,
  kLCGVariate = 1,
  kMin = 2,
  kMax = 3,
  kMean = 4,
  kAlternateVariate = 5,
};

Instruction byte_to_instruction(uint8_t byte) {
  return static_cast<Instruction>(byte % 6);
}

}  // namespace

FuzzingBitGen::FuzzingBitGen(absl::Span<const uint8_t> data_stream,
                             absl::Span<const uint8_t> control_stream,
                             uint64_t seed_value)
    : control_stream_(control_stream), data_stream_(data_stream) {
  seed(seed_value);
}

void FuzzingBitGen::DataStreamFn(bool use_lcg, void* result,
                                 size_t result_size) {
  if (!use_lcg && !data_stream_.empty()) {
    // Consume up to result_size bytes from the data stream.
    size_t n =
        result_size < data_stream_.size() ? result_size : data_stream_.size();
    memcpy(result, data_stream_.data(), n);
    data_stream_.remove_prefix(n);
    return;
  }

  // The stream is expired. Generate up to 16 bytes from the LCG.
  state_ = lcg(state_);
  uint64_t x = mix(state_);
  memcpy(result, &x, result_size > sizeof(x) ? sizeof(x) : result_size);
  if (result_size > sizeof(x)) {
    state_ = lcg(state_);
    uint64_t x = mix(state_);
    memcpy(static_cast<uint8_t*>(result) + sizeof(x), &x,
           result_size - sizeof(x) > sizeof(x) ? sizeof(x)
                                               : result_size - sizeof(x));
  }
}

uint64_t FuzzingBitGen::operator()() {
  // Use the control stream to determine the return value.
  if (c_ >= control_stream_.size()) {
    c_ = 0;
  }
  Instruction instruction =
      control_stream_.empty()
          ? (data_stream_.empty() ? Instruction::kLCGVariate
                                  : Instruction::kDataStreamVariate)
          : byte_to_instruction(control_stream_[c_++]);
  switch (instruction) {
    case Instruction::kMin:
      return 0;  // min
    case Instruction::kMax:
      return (std::numeric_limits<uint64_t>::max)();  // max
    case Instruction::kMean:
      return (std::numeric_limits<uint64_t>::max)() / 2;  // mean
    default:
      break;
  }
  uint64_t x = 0;
  DataStreamFn(instruction == Instruction::kLCGVariate, &x, sizeof(x));
  return x;
}

void FuzzingBitGen::seed(result_type seed_value) {
  absl::uint128 tmp = seed_value;
  state_ = lcg(tmp + increment());
}

bool FuzzingBitGen::InvokeMock(absl::FastTypeIdType key_id, void* args_tuple,
                               void* result) {
  using FuzzMapT = absl::flat_hash_map<absl::FastTypeIdType,
                                       internal::TypeErasedFuzzFunctionT>;
  static const absl::NoDestructor<FuzzMapT> fuzzing_map([]() {
    FuzzMapT map;
    auto register_fn = [&map](absl::FastTypeIdType key, auto fn) {
      map[key] = fn;
    };
    internal::RegisterAbslRandomFuzzingMocks(register_fn);
    return map;
  }());

  auto it = fuzzing_map->find(key_id);
  if (it == fuzzing_map->end()) {
    return false;
  }

  if (c_ >= control_stream_.size()) {
    c_ = 0;
  }
  uint8_t control_byte = control_stream_.empty() ? 0 : control_stream_[c_++];
  const bool use_lcg =
      byte_to_instruction(control_byte) == Instruction::kLCGVariate;
  auto data_stream_fn = [this, use_lcg](void* result, size_t n) {
    this->DataStreamFn(use_lcg, result, n);
  };

  it->second(data_stream_fn, control_byte, args_tuple, result);
  return true;
}

}  // namespace fuzztest
