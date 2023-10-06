#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "gtest/gtest.h"
#include "./fuzztest/domain_core.h"
#include "./fuzztest/fuzztest.h"
#include "./fuzztest/init_fuzztest.h"

constexpr static size_t kByteArrayMaxLen = 4096;

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size);

auto ArbitraryByteVector() {
  return fuzztest::Arbitrary<std::vector<uint8_t>>().WithMaxSize(
      kByteArrayMaxLen);
}

void TestOneInput(const std::vector<uint8_t>& data) {
  LLVMFuzzerTestOneInput(const_cast<uint8_t*>(data.data()), data.size());
}

FUZZ_TEST(LLVMFuzzer, TestOneInput).WithDomains(ArbitraryByteVector());

int main(int argc, char** argv) {
  return RUN_ALL_TESTS();
}
