#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "gtest/gtest.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "./fuzztest/fuzztest.h"
#include "./fuzztest/init_fuzztest.h"
#include "./fuzztest/internal/domains/arbitrary_impl.h"
#include "./fuzztest/internal/domains/container_of_impl.h"
#include "./fuzztest/internal/domains/domain_base.h"

constexpr static size_t kByteArrayMaxLen = 4096;

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size);

extern "C" int __attribute__((weak))
LLVMFuzzerInitialize(int* argc, char*** argv);

extern "C" size_t __attribute__((weak))
LLVMFuzzerCustomMutator(uint8_t* data, size_t size, size_t max_size,
                        unsigned int seed);

// TODO(b/303267857): Migrate fuzz targets that use this feature manually.
// `LLVMFuzzerCustomCrossOver` is defined to produce a link-error (duplicate
// definition) if it's also defined by user.
extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t* data1, size_t size1,
                                            const uint8_t* data2, size_t size2,
                                            uint8_t* out, size_t max_out_size,
                                            unsigned int seed) {
  std::cerr << "LLVMFuzzerCustomCrossOver is not supported in FuzzTest\n";
  exit(-1);
}

template <typename T>
class InplaceVector {
 public:
  using iterator = T*;
  using value_type = T;

  InplaceVector() : data_(nullptr), size_(0) {}
  InplaceVector(T* data, std::size_t size) : data_(data), size_(size) {}

  T& operator[](int i) { return data_[i]; }

  T const& operator[](int i) const { return data_[i]; }

  std::size_t size() const { return size_; }

  T* begin() const { return data_; }

  T* end() const { return data_ + size_; }

  void insert(T* index, T val) {
    for (T* itr = data_ + size_; itr > index; --itr) {
      *itr = *(itr - 1);
    }
    *index = val;
    ++size_;
  }

  void erase(T* index) {
    for (T* itr = index; itr < data_ + size_ - 1; ++itr) {
      *itr = *(itr + 1);
    }
    --size_;
  }

  void erase(T* begin, T* end) {
    for (T *itr = begin, *jtr = end; jtr < data_ + size_; ++itr, ++jtr) {
      *itr = *jtr;
    }
    size_ -= (end - begin);
  }

 private:
  T* data_;
  std::size_t size_;
};

extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size,
                                   size_t max_size) {
  static auto domain = fuzztest::internal::SequenceContainerOfImpl<
      InplaceVector<uint8_t>, fuzztest::internal::ArbitraryImpl<uint8_t>>();
  domain.WithMaxSize(max_size);
  absl::BitGen bitgen;
  InplaceVector<uint8_t> val(data, size);
  domain.Mutate(val, bitgen, false);
  return val.size();
}

class ArbitraryByteVector
    : public fuzztest::internal::SequenceContainerOfImpl<
          std::vector<uint8_t>, fuzztest::internal::ArbitraryImpl<uint8_t>> {
  using Base = typename ArbitraryByteVector::ContainerOfImplBase;

 public:
  using typename Base::corpus_type;

  ArbitraryByteVector() { WithMaxSize(kByteArrayMaxLen); }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    if (LLVMFuzzerCustomMutator) {
      const size_t size = val.size();
      const size_t max_size = only_shrink ? size : kByteArrayMaxLen;
      val.resize(max_size);
      val.resize(LLVMFuzzerCustomMutator(val.data(), size, max_size, prng()));
    } else {
      Base::Mutate(val, prng, only_shrink);
    }
  }
};

void TestOneInput(const std::vector<uint8_t>& data) {
  LLVMFuzzerTestOneInput(const_cast<uint8_t*>(data.data()), data.size());
}

FUZZ_TEST(LLVMFuzzer, TestOneInput).WithDomains(ArbitraryByteVector());

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, &argv);
  if (LLVMFuzzerInitialize) {
    LLVMFuzzerInitialize(&argc, &argv);
  }
  fuzztest::InitFuzzTest(&argc, &argv);
  return RUN_ALL_TESTS();
}
