// A LLVM fuzzer puzzle that are supposed be solvable with the custom mutator
// calling LLVMFuzzerMutate (with auto-dictionary support).

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <string>

extern "C" size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

static void Transform(char *data, size_t size) {
  for (char *c = data; c < data + size; ++c) {
    if (*c < std::numeric_limits<char>::max()) ++*c;
  }
}

static void InvTransform(char *data, size_t size) {
  for (char *c = data; c < data + size; ++c) {
    if (*c > std::numeric_limits<char>::min()) --*c;
  }
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                          size_t max_size, unsigned int seed) {
  size = LLVMFuzzerMutate(data, size, max_size);
  InvTransform(reinterpret_cast<char *>(data), size);
  return size;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string s = {reinterpret_cast<const char *>(data), size};
  Transform(s.data(), size);
  if (s == "bingo") {
    std::abort();
  }
  return 0;
}
