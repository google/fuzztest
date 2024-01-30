// Copyright 2024 Google LLC
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

#include <cstdlib>

#include "./fuzztest/fuzztest.h"
#include "./fuzztest/internal/test_protobuf.pb.h"

namespace {

using fuzztest::internal::TestProtobuf;

void BytesSummingToMagicValue(const TestProtobuf& input) {
  char sum = 0;
  for (const char c : input.str()) {
    sum += c;
  }
  if (sum == 0x72) {
    std::abort();
  }
}
FUZZ_TEST(ProtoPuzzles, BytesSummingToMagicValue);

void PrefixBytesSummingToMagicValue(const TestProtobuf& input) {
  if (input.str().size() < 2) {
    return;
  }
  if (input.str()[0] + input.str()[1] == 0x72) {
    std::abort();
  }
}
FUZZ_TEST(ProtoPuzzles, PrefixBytesSummingToMagicValue);

void PrefixIsMagicValue(const TestProtobuf& input) {
  if (input.str().size() < 2) {
    return;
  }
  if (input.str()[0] + input.str()[1] == 0x72) {
    std::abort();
  }
}
FUZZ_TEST(ProtoPuzzles, PrefixIsMagicValue);

}  // namespace
