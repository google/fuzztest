#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/log/check.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/fuzztest.h"
#include "./fuzztest/init_fuzztest.h"
#include "./fuzztest/internal/domains/arbitrary_impl.h"
#include "./fuzztest/internal/domains/container_of_impl.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/io.h"
#include "re2/re2.h"

ABSL_FLAG(std::string, llvm_fuzzer_wrapper_dict_file, "",
          "Path to dictionary file used by the wrapped legacy LLVMFuzzer "
          "target (https://llvm.org/docs/LibFuzzer.html#fuzz-target).");
ABSL_FLAG(std::string, llvm_fuzzer_wrapper_corpus_dir, "",
          "Path to seed corpus directory used by the wrapped legacy LLVMFuzzer "
          "target (https://llvm.org/docs/LibFuzzer.html#fuzz-target).");

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

std::vector<std::vector<uint8_t>> ReadByteArraysFromDirectory() {
  const std::string flag = absl::GetFlag(FLAGS_llvm_fuzzer_wrapper_corpus_dir);
  if (flag.empty()) return {};
  std::vector<fuzztest::internal::FilePathAndData> files =
      fuzztest::internal::ReadFileOrDirectory(flag);

  std::vector<std::vector<uint8_t>> out;
  out.reserve(files.size());
  for (const fuzztest::internal::FilePathAndData& file : files) {
    out.push_back(
        {file.data.begin(),
         file.data.begin() + std::min(file.data.size(), kByteArrayMaxLen)});
  }
  return out;
}

std::vector<std::vector<uint8_t>> ReadByteArrayDictionaryFromFile() {
  const std::string flag = absl::GetFlag(FLAGS_llvm_fuzzer_wrapper_dict_file);
  if (flag.empty()) return {};
  std::vector<fuzztest::internal::FilePathAndData> files =
      fuzztest::internal::ReadFileOrDirectory(flag);

  std::vector<std::vector<uint8_t>> out;
  out.reserve(files.size());
  // Dictionary must be in the format specified at
  // https://llvm.org/docs/LibFuzzer.html#dictionaries
  constexpr absl::string_view kLineRegex =
      "[^\\\"]*"      // Skip an arbitrary prefix.
      "\\\"(.+)\\\""  // Must be enclosed in quotes.
      "[^\\\"]*";     // Skip an arbitrary suffix.
  for (const fuzztest::internal::FilePathAndData& file : files) {
    for (absl::string_view line : absl::StrSplit(file.data, '\n')) {
      if (line.empty() || line[0] == '#') continue;
      std::string entry;
      CHECK(RE2::FullMatch(line, kLineRegex, &entry))
          << "Invalid dictionary entry: " << line;
      std::string unescaped_entry;
      CHECK(absl::CUnescape(entry, &unescaped_entry))
          << "Could not unescape: " << entry;
      out.emplace_back(unescaped_entry.begin(), unescaped_entry.end());
    }
  }
  return out;
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

FUZZ_TEST(LLVMFuzzer, TestOneInput)
    .WithDomains(ArbitraryByteVector()
                     .WithDictionary(ReadByteArrayDictionaryFromFile)
                     .WithSeeds(ReadByteArraysFromDirectory));

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, &argv);
  if (LLVMFuzzerInitialize) {
    LLVMFuzzerInitialize(&argc, &argv);
  }
  fuzztest::InitFuzzTest(&argc, &argv);
  return RUN_ALL_TESTS();
}
