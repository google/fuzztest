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
#include "./fuzztest/internal/fuzzing_mock_stream.h"
#include "./fuzztest/internal/register_fuzzing_mocks.h"

namespace fuzztest {
namespace {

using FuzzingMockStream = ::fuzztest::internal::FuzzingMockStream;
using Instruction = FuzzingMockStream::Instruction;

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

Instruction GetNextInstruction(absl::Span<const uint8_t>& control_stream) {
  if (control_stream.empty()) {
    return Instruction::kDataStreamVariate;
  }
  uint8_t v = control_stream[0];
  control_stream.remove_prefix(1);
  return static_cast<Instruction>(v % 6);
}

}  // namespace

FuzzingBitGen::FuzzingBitGen(absl::Span<const uint8_t> data_stream,
                             absl::Span<const uint8_t> control_stream,
                             uint64_t seed_value)
    : control_stream_(control_stream), data_stream_(data_stream) {
  seed(seed_value);
}

FuzzingBitGen::FuzzingBitGen(absl::Span<const uint8_t> data_stream)
    : control_stream_({}), data_stream_(data_stream) {
  // Seed the internal URBG with the first 8 bytes of the data stream.
  uint64_t stream_seed = 0x6C7FD535EDC7A62D;
  if (!data_stream_.empty()) {
    size_t num_bytes = std::min(sizeof(stream_seed), data_stream_.size());
    std::memcpy(&stream_seed, data_stream_.data(), num_bytes);
    data_stream_.remove_prefix(num_bytes);
  }
  seed(stream_seed);
}

void FuzzingBitGen::DataStreamFn(bool use_lcg, void* result,
                                 size_t result_size) {
  if (!use_lcg && !data_stream_.empty()) {
    // Consume up to result_size bytes from the data stream and copy to result.
    // leaving the remaining bytes unchanged.
    size_t n = std::min(result_size, data_stream_.size());
    memcpy(result, data_stream_.data(), n);
    data_stream_.remove_prefix(n);
    return;
  }

  // The stream is expired. Generate up to 16 bytes from the LCG, and copy to
  // result, leaving the remaining bytes unchanged.
  //
  // NOTE: This will satisfy uniform values up to uint128, however it
  // will not fill longer string values.
  urbg_state_ = lcg(urbg_state_);
  uint64_t x = mix(urbg_state_);
  memcpy(result, &x, std::min(result_size, sizeof(x)));
  if (result_size > sizeof(x)) {
    urbg_state_ = lcg(urbg_state_);
    x = mix(urbg_state_);
    memcpy(static_cast<uint8_t*>(result) + sizeof(x), &x,
           std::min(result_size - sizeof(x), sizeof(x)));
  }
}

uint64_t FuzzingBitGen::operator()() {
  // Use the control stream to determine the return value.
  Instruction instruction = GetNextInstruction(control_stream_);
  switch (instruction) {
    case Instruction::kMin:
      return 0;
    case Instruction::kMax:
      return (std::numeric_limits<uint64_t>::max)();
    case Instruction::kMean:
      return (std::numeric_limits<uint64_t>::max)() / 2;
    default:
      break;
  }
  uint64_t x = 0;
  DataStreamFn(instruction == Instruction::kLCGVariate, &x, sizeof(x));
  return x;
}

void FuzzingBitGen::seed(result_type seed_value) {
  absl::uint128 tmp = seed_value;
  urbg_state_ = lcg(tmp + increment());
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

  Instruction instruction = GetNextInstruction(control_stream_);
  bool use_lcg = instruction == Instruction::kLCGVariate;
  it->second(FuzzingMockStream(
                 [this, use_lcg](void* result, size_t n) {
                   this->DataStreamFn(use_lcg, result, n);
                 },
                 instruction),
             args_tuple, result);
  return true;
}

}  // namespace fuzztest
