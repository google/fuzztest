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

#include "./fuzztest/internal/domains/flatbuffers_domain_impl.h"

#include <cstdint>
#include <optional>
#include <type_traits>
#include <utility>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/synchronization/mutex.h"
#include "flatbuffers/base.h"
#include "flatbuffers/flatbuffer_builder.h"
#include "flatbuffers/reflection_generated.h"
#include "flatbuffers/table.h"
#include "./fuzztest/domain_core.h"
#include "./fuzztest/internal/any.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/domain_type_erasure.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"

namespace fuzztest {
namespace internal {

FlatbuffersUnionDomainImpl::corpus_type FlatbuffersUnionDomainImpl::Init(
    absl::BitGenRef prng) {
  if (auto seed = this->MaybeGetRandomSeed(prng)) {
    return *seed;
  }
  corpus_type val;
  auto selected_type_enumval_index =
      absl::Uniform(prng, 0ul, union_def_->values()->size());
  auto type_enumval = union_def_->values()->Get(selected_type_enumval_index);
  if (type_enumval == nullptr) {
    return val;
  }
  auto type_value = type_domain_.FromValue(type_enumval->value());
  if (!type_value.has_value()) {
    return val;
  }
  val.first = *type_value;
  if (type_enumval->value() == 0 /* NONE */) {
    return val;
  }

  auto domain = GetTableDomain(*type_enumval);
  if (domain == nullptr) {
    return val;
  }

  auto inner_val = domain->Init(prng);
  val.second = GenericDomainCorpusType(std::in_place_type<decltype(inner_val)>,
                                       std::move(inner_val));
  return val;
}

// Mutates the corpus value.
void FlatbuffersUnionDomainImpl::Mutate(
    corpus_type& val, absl::BitGenRef prng,
    const domain_implementor::MutationMetadata& metadata, bool only_shrink) {
  auto total_weight = CountNumberOfFields(val);
  auto selected_weight = absl::Uniform(prng, 0ul, total_weight);
  if (selected_weight == 0) {
    type_domain_.Mutate(val.first, prng, metadata, only_shrink);
    val.second = GenericDomainCorpusType(std::in_place_type<void*>, nullptr);
    auto type_value = type_domain_.GetValue(val.first);
    if (type_value == 0) {
      return;
    }
    auto type_enumval = union_def_->values()->LookupByKey(type_value);
    if (type_enumval == nullptr) {
      return;
    }
    auto domain = GetTableDomain(*type_enumval);
    if (domain == nullptr) {
      return;
    }
    auto inner_val = domain->Init(prng);
    val.second = GenericDomainCorpusType(
        std::in_place_type<decltype(inner_val)>, std::move(inner_val));
  } else {
    auto type_value = type_domain_.GetValue(val.first);
    auto type_enumval = union_def_->values()->LookupByKey(type_value);
    if (type_enumval == nullptr) {
      return;
    }
    auto domain = GetTableDomain(*type_enumval);
    if (domain == nullptr) {
      return;
    }
    auto inner_val = val.second.template GetAs<
        corpus_type_t<std::remove_pointer_t<decltype(domain)>>>();
    domain->MutateSelectedField(inner_val, prng, metadata, only_shrink,
                                selected_weight - 1);
  }
}

uint64_t FlatbuffersUnionDomainImpl::CountNumberOfFields(corpus_type& val) {
  uint64_t count = 1;
  auto type_value = type_domain_.GetValue(val.first);
  if (type_value == 0 /* NONE */) {
    return count;
  }
  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return count;
  }
  auto domain = GetTableDomain(*type_enumval);
  if (domain != nullptr) {
    auto inner_val = val.second.template GetAs<
        corpus_type_t<std::remove_pointer_t<decltype(domain)>>>();
    count += domain->CountNumberOfFields(inner_val);
  }
  return count;
}

absl::Status FlatbuffersUnionDomainImpl::ValidateCorpusValue(
    const corpus_type& corpus_value) const {
  auto type_value = type_domain_.GetValue(corpus_value.first);
  if (type_value == 0) {
    return absl::OkStatus();
  }
  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return absl::OkStatus();
  }
  auto domain = GetTableDomain(*type_enumval);
  if (domain == nullptr) {
    return absl::OkStatus();
  }
  auto inner_corpus_value = corpus_value.second.template GetAs<
      corpus_type_t<std::remove_pointer_t<decltype(domain)>>>();
  return domain->ValidateCorpusValue(inner_corpus_value);
}

std::optional<FlatbuffersUnionDomainImpl::corpus_type>
FlatbuffersUnionDomainImpl::FromValue(const value_type& value) const {
  std::optional<FlatbuffersUnionDomainImpl::corpus_type> out{{}};
  auto type_value = type_domain_.FromValue(value.first);
  if (type_value.has_value()) {
    out->first = *type_value;
  }
  auto type_enumval = union_def_->values()->LookupByKey(value.first);
  if (type_enumval == nullptr) {
    return std::nullopt;
  }
  auto domain = GetTableDomain(*type_enumval);
  if (domain != nullptr) {
    auto inner_value =
        domain->FromValue(static_cast<const flatbuffers::Table*>(value.second));
    if (inner_value.has_value()) {
      out->second = GenericDomainCorpusType(
          std::in_place_type<typename decltype(inner_value)::value_type>,
          std::move(*inner_value));
    }
  }
  return out;
}

// Converts the IRObject to a corpus value.
std::optional<FlatbuffersUnionDomainImpl::corpus_type>
FlatbuffersUnionDomainImpl::ParseCorpus(const IRObject& obj) const {
  corpus_type out;
  auto subs = obj.Subs();
  if (!subs) {
    return std::nullopt;
  }
  if (subs->size() != 2) {
    return std::nullopt;
  }

  auto type_corpus = type_domain_.ParseCorpus((*subs)[0]);
  if (!type_corpus.has_value()) {
    return std::nullopt;
  }
  out.first = *type_corpus;
  auto type_value = type_domain_.GetValue(out.first);
  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return std::nullopt;
  }
  auto domain = GetTableDomain(*type_enumval);
  if (domain == nullptr) {
    return std::nullopt;
  }

  auto inner_corpus = domain->ParseCorpus((*subs)[1]);
  if (inner_corpus.has_value()) {
    out.second = GenericDomainCorpusType(
        std::in_place_type<
            typename std::remove_pointer_t<decltype(inner_corpus)>::value_type>,
        *inner_corpus);
  }
  return out;
}

// Converts the corpus value to an IRObject.
IRObject FlatbuffersUnionDomainImpl::SerializeCorpus(
    const corpus_type& value) const {
  IRObject out;
  auto& pair = out.MutableSubs();
  pair.reserve(2);

  auto type_value = type_domain_.GetValue(value.first);
  pair.push_back(type_domain_.SerializeCorpus(value.first));

  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return out;
  }
  auto domain = GetTableDomain(*type_enumval);
  if (domain == nullptr) {
    return out;
  }
  pair.push_back(domain->SerializeCorpus(
      value.second.template GetAs<
          corpus_type_t<std::remove_pointer_t<decltype(domain)>>>()));
  return out;
}

std::optional<flatbuffers::uoffset_t> FlatbuffersUnionDomainImpl::BuildValue(
    const corpus_type& value, flatbuffers::FlatBufferBuilder& builder) const {
  auto type_value = type_domain_.GetValue(value.first);
  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return std::nullopt;
  }
  auto domain = GetTableDomain(*type_enumval);
  if (domain == nullptr) {
    return std::nullopt;
  }
  return domain->BuildTable(
      value.second.template GetAs<
          corpus_type_t<std::remove_pointer_t<decltype(domain)>>>(),
      builder);
}

FlatbuffersTableUntypedDomainImpl* FlatbuffersUnionDomainImpl::GetTableDomain(
    const reflection::EnumVal& enum_value) const {
  absl::MutexLock l(&mutex_);
  auto it = domains_.find(enum_value.value());
  if (it == domains_.end()) {
    auto base_type = enum_value.union_type()->base_type();
    if (base_type == reflection::BaseType::None) {
      return nullptr;
    }
    FUZZTEST_INTERNAL_CHECK(base_type == reflection::BaseType::Obj,
                            "EnumVal union type is not a BaseType::Obj");
    auto object = schema_->objects()->Get(enum_value.union_type()->index());
    if (object->is_struct()) {
      // TODO(b/405939014): Support structs.
      return nullptr;
    }
    it = domains_
             .emplace(enum_value.value(),
                      FlatbuffersTableUntypedDomainImpl{schema_, object})
             .first;
  }
  return &it->second;
}

void FlatbuffersUnionDomainImpl::Printer::PrintCorpusValue(
    const corpus_type& value, domain_implementor::RawSink out,
    domain_implementor::PrintMode mode) const {
  auto type_value = self.type_domain_.GetValue(value.first);
  auto type_enumval = self.union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return;
  }
  absl::Format(out, "<%s>(", type_enumval->name()->str());
  auto domain = self.GetTableDomain(*type_enumval);
  if (domain == nullptr) {
    absl::Format(out, "UNSUPPORTED_UNION_TYPE");
    return;
  }
  auto inner_corpus_value = value.second.template GetAs<
      corpus_type_t<std::remove_pointer_t<decltype(domain)>>>();
  domain_implementor::PrintValue(*domain, inner_corpus_value, out, mode);
  absl::Format(out, ")");
}
}  // namespace internal
}  // namespace fuzztest
