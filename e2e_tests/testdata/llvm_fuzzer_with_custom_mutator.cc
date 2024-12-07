// A LLVM fuzzer puzzle that are supposed be solvable with the custom mutator
// calling LLVMFuzzerMutate (with auto-dictionary support).

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

extern "C" size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                          size_t max_size, unsigned int seed) {
  size = LLVMFuzzerMutate(data, size, max_size);
  std::reverse(data, data + size);
  return size;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string s = {reinterpret_cast<const char *>(data), size};
  std::reverse(s.begin(), s.end());
  if (s == "bingo") {
    std::abort();
  }
  // Testing that calling LLVMFuzzerMutate outside of the custom mutator should
  // not cause crashes.
  LLVMFuzzerMutate(reinterpret_cast<uint8_t *>(s.data()), s.size(), s.size());
  return 0;
}
