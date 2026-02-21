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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_BIT_GEN_REF_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_BIT_GEN_REF_H_

#include <cassert>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include "absl/random/bit_gen_ref.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "./common/logging.h"
#include "./fuzztest/fuzzing_bit_gen.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/printer.h"
#include "./fuzztest/internal/serialization.h"

namespace fuzztest::internal {

// The fuzztest "corpus value" holds the fuzzed data stream and a
// maybe-initialized instance of a fuzz-test specific URBG which is bound to
// an absl::BitGenRef in BitGenRefDomain::GetValue.
//
// The URBG instance is lazily initialized when GetBitGen is called and
// destroyed when CleanupBitGen is called.
class BitGenCorpusValue {
 public:
  using URBG = FuzzingBitGen;

  explicit BitGenCorpusValue(std::vector<uint8_t> data,
                             std::vector<uint8_t> control, uint64_t seed)
      : data_(std::move(data)), control_(std::move(control)), seed_(seed) {}
  ~BitGenCorpusValue() { CleanupBitGen(); }

  // Copy and move do not initialize the internal URBG instance.
  BitGenCorpusValue(const BitGenCorpusValue& o)
      : data_(o.data_),
        control_(o.control_),
        seed_(o.seed_),
        bitgen_(std::nullopt) {}
  BitGenCorpusValue& operator=(const BitGenCorpusValue& o) {
    // The internal URBG should be unused.
    FUZZTEST_CHECK(!bitgen_.has_value());
    data_ = o.data_;
    control_ = o.control_;
    seed_ = o.seed_;
    return *this;
  }
  BitGenCorpusValue(BitGenCorpusValue&& o)
      : data_(std::move(o.data_)),
        control_(std::move(o.control_)),
        seed_(std::move(o.seed_)),
        bitgen_(std::nullopt) {}
  BitGenCorpusValue& operator=(BitGenCorpusValue&& o) {
    // The internal URBG should be unused.
    FUZZTEST_CHECK(!o.bitgen_.has_value());
    FUZZTEST_CHECK(!bitgen_.has_value());
    data_ = std::move(o.data_);
    control_ = std::move(o.control_);
    seed_ = o.seed_;
    return *this;
  }

  std::vector<uint8_t>& data() { return data_; }
  const std::vector<uint8_t>& data() const { return data_; }

  std::vector<uint8_t>& control() { return control_; }
  const std::vector<uint8_t>& control() const { return control_; }

  uint64_t& seed() { return seed_; }
  const uint64_t& seed() const { return seed_; }

  // Cleanup the internal URBG instance.
  void CleanupBitGen() { bitgen_.reset(); }

  // Returns a reference to the URBG instance.
  // If it has not been initialized, it will be initialized.
  // NOTE: The returned reference is valid until the next call to CleanupBitGen.
  URBG& GetBitGen() const {
    if (!bitgen_.has_value()) {
      bitgen_.emplace(data_, control_, seed_);
    }
    return *bitgen_;
  }

 private:
  // Inputs to the FuzzingBitGen constructor which must outlive it.
  std::vector<uint8_t> data_;     // fuzztest generated data stream.
  std::vector<uint8_t> control_;  // fuzztest generated control stream.
  uint64_t seed_;                 // fuzztest generated seed.
  mutable std::optional<URBG> bitgen_;
};

// A FuzzTest domain for an absl::BitGenRef, which is an arbitrary
// uniform random bit generator and can be used for functions accepting an
// absl::BitGenRef, such as absl::Uniform and other Abseil distribution
// functions. The generated sequences will be stable across executions, though
// it may occasionally be broken when there are changes to the underlying
// implementation such as adding support for new distributions, etc.
//
// The domain accepts an input "data stream" corpus which is used to initialize
// a FuzzingBitGen instance. This internal FuzzingBitGen instance is bound to an
// absl::BitGenRef when GetValue is called. The control stream is reused
// (wrapped around) when exhausted. The data stream falls back to an LCG PRNG
// when exhausted.
//
// BitGenRefDomain does not support seeded domains.
// BitGenRefDomain does not support GetRandomValue.
template <typename DataSequence, typename ControlSequence, typename SeedValue>
class BitGenRefDomain
    : public domain_implementor::DomainBase<
          BitGenRefDomain<DataSequence, ControlSequence, SeedValue>,
          /*value_type=*/absl::BitGenRef, BitGenCorpusValue> {
 public:
  using typename BitGenRefDomain::DomainBase::corpus_type;
  using typename BitGenRefDomain::DomainBase::value_type;

  explicit BitGenRefDomain(const DataSequence& data,
                           const ControlSequence& control,
                           const SeedValue& seed_value)
      : data_(data), control_(control), seed_value_(seed_value) {}

  BitGenRefDomain(const BitGenRefDomain&) = default;
  BitGenRefDomain(BitGenRefDomain&&) = default;
  BitGenRefDomain& operator=(const BitGenRefDomain&) = default;
  BitGenRefDomain& operator=(BitGenRefDomain&&) = default;

  corpus_type Init(absl::BitGenRef prng) {
    auto data = data_.Init(prng);
    auto control = control_.Init(prng);
    auto seed_value = seed_value_.Init(prng);
    return corpus_type{data_.GetValue(data), control_.GetValue(control),
                       seed_value_.GetValue(seed_value)};
  }
  void Mutate(corpus_type& corpus_value, absl::BitGenRef prng,
              const domain_implementor::MutationMetadata& metadata,
              bool only_shrink) {
    corpus_value.CleanupBitGen();
    auto data_corpus = data_.FromValue(corpus_value.data());
    if (data_corpus.has_value()) {
      data_.Mutate(*data_corpus, prng, metadata, only_shrink);
      corpus_value.data() = data_.GetValue(*data_corpus);
    }
    auto control_corpus = control_.FromValue(corpus_value.control());
    if (control_corpus.has_value()) {
      control_.Mutate(*control_corpus, prng, metadata, only_shrink);
      corpus_value.control() = control_.GetValue(*control_corpus);
    }
    auto seed_corpus = seed_value_.FromValue(corpus_value.seed());
    if (seed_corpus.has_value()) {
      seed_value_.Mutate(*seed_corpus, prng, metadata, only_shrink);
      corpus_value.seed() = seed_value_.GetValue(*seed_corpus);
    }
  }

  value_type GetValue(const corpus_type& corpus_value) const {
    return corpus_value.GetBitGen();
  }

  value_type GetRandomValue(absl::BitGenRef prng) {
    // See b/404828355
    FUZZTEST_LOG(FATAL) << "The domain doesn't support GetRandomValue().";
  }

  std::optional<corpus_type> FromValue(const value_type&) const {
    // No conversion from absl::BitGenRef back to corpus.
    return std::nullopt;
  }

  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const {
    absl::Status status;
    auto data_corpus = data_.FromValue(corpus_value.data());
    if (!data_corpus.has_value()) {
      return absl::InvalidArgumentError("Invalid data stream");
    }
    auto control_corpus = control_.FromValue(corpus_value.control());
    if (!control_corpus.has_value()) {
      return absl::InvalidArgumentError("Invalid control stream");
    }
    auto seed_corpus = seed_value_.FromValue(corpus_value.seed());
    if (!seed_corpus.has_value()) {
      return absl::InvalidArgumentError("Invalid seed value");
    }
    status.Update(data_.ValidateCorpusValue(*data_corpus));
    status.Update(control_.ValidateCorpusValue(*control_corpus));
    status.Update(seed_value_.ValidateCorpusValue(*seed_corpus));
    return status;
  }

  void UpdateMemoryDictionary(
      const corpus_type& corpus_value,
      domain_implementor::ConstCmpTablesPtr cmp_tables) {
    auto data_corpus = data_.FromValue(corpus_value.data());
    auto control_corpus = control_.FromValue(corpus_value.control());
    auto seed_corpus = seed_value_.FromValue(corpus_value.seed());
    assert(data_corpus.has_value());
    assert(control_corpus.has_value());
    assert(seed_corpus.has_value());
    data_.UpdateMemoryDictionary(*data_corpus, cmp_tables);
    control_.UpdateMemoryDictionary(*control_corpus, cmp_tables);
    seed_value_.UpdateMemoryDictionary(*seed_corpus, cmp_tables);
  }

  std::optional<corpus_type> ParseCorpus(const internal::IRObject& obj) const {
    auto container = obj.Subs();
    if (container && container->size() == 3) {
      auto x = data_.ParseCorpus((*container)[0]);
      auto y = control_.ParseCorpus((*container)[1]);
      auto z = seed_value_.ParseCorpus((*container)[2]);
      if (x.has_value() && y.has_value() && z.has_value()) {
        return corpus_type(data_.GetValue(*x), control_.GetValue(*y),
                           seed_value_.GetValue(*z));
      }
    }
    return std::nullopt;
  }

  internal::IRObject SerializeCorpus(const corpus_type& corpus_value) const {
    auto data_corpus = data_.FromValue(corpus_value.data());
    auto control_corpus = control_.FromValue(corpus_value.control());
    auto seed_corpus = seed_value_.FromValue(corpus_value.seed());
    assert(data_corpus.has_value());
    assert(control_corpus.has_value());
    assert(seed_corpus.has_value());

    internal::IRObject obj;
    auto& v = obj.MutableSubs();
    v.reserve(3);
    v.emplace_back(data_.SerializeCorpus(*data_corpus));
    v.emplace_back(control_.SerializeCorpus(*control_corpus));
    v.emplace_back(seed_value_.SerializeCorpus(*seed_corpus));
    return obj;
  }

  auto GetPrinter() const { return Printer{}; }

 private:
  struct Printer {
    void PrintCorpusValue(const corpus_type& val,
                          domain_implementor::RawSink out,
                          domain_implementor::PrintMode mode) const {
      absl::Format(out, "absl::BitGenRef{}");
    }
  };

  DataSequence data_;
  ControlSequence control_;
  SeedValue seed_value_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_BIT_GEN_REF_H_
