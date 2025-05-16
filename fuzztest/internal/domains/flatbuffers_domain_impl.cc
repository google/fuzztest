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
#include <utility>
#include <vector>

#include "absl/base/nullability.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "flatbuffers/base.h"
#include "flatbuffers/flatbuffer_builder.h"
#include "flatbuffers/reflection_generated.h"
#include "flatbuffers/struct.h"
#include "flatbuffers/table.h"
#include "./fuzztest/domain_core.h"
#include "./fuzztest/internal/any.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/domain_type_erasure.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"

namespace fuzztest {
namespace internal {

// Gets a domain for a specific struct type.
template <>
auto FlatbuffersUnionDomainImpl::GetDomainForType<FlatbuffersStructTag>(
    const reflection::EnumVal& enum_value) const {
  const reflection::Object* object =
      schema_->objects()->Get(enum_value.union_type()->index());
  return Domain<const flatbuffers::Struct*>(
      FlatbuffersStructUntypedDomainImpl{schema_, object});
}

// Gets a domain for a specific table type.
template <>
auto FlatbuffersUnionDomainImpl::GetDomainForType<FlatbuffersTableTag>(
    const reflection::EnumVal& enum_value) const {
  const reflection::Object* object =
      schema_->objects()->Get(enum_value.union_type()->index());
  return Domain<const flatbuffers::Table*>(
      FlatbuffersTableUntypedDomainImpl{schema_, object});
}

FlatbuffersUnionDomainImpl::corpus_type FlatbuffersUnionDomainImpl::Init(
    absl::BitGenRef prng) {
  if (auto seed = this->MaybeGetRandomSeed(prng)) {
    return *seed;
  }

  // Unions are encoded as the combination of two fields: an enum representing
  // the union choice and the offset to the actual element.
  //
  // The following code follows that logic.
  corpus_type val;

  // Prepare `union_choice`.
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

  // FlatBuffers reserves the enumeration constant NONE (encoded as 0) to mean
  // that the union field is not set.
  if (type_enumval->value() == 0 /* NONE */) {
    return val;
  }

  const reflection::Object* object =
      schema_->objects()->Get(type_enumval->union_type()->index());
  if (object->is_struct()) {
    auto inner_val =
        GetSubDomain<FlatbuffersStructTag>(*type_enumval).Init(prng);
    val.second = std::move(inner_val);
  } else {
    auto inner_val =
        GetSubDomain<FlatbuffersTableTag>(*type_enumval).Init(prng);
    val.second = std::move(inner_val);
  }
  return val;
}

// Mutates the corpus value.
void FlatbuffersUnionDomainImpl::Mutate(
    corpus_type& val, absl::BitGenRef prng,
    const domain_implementor::MutationMetadata& metadata, bool only_shrink) {
  auto total_weight = CountNumberOfFields(val);
  auto selected_weight = absl::Uniform(prng, 0ul, total_weight);
  if (selected_weight == 0) {
    // Mutate both type and value.

    // Deal with the type.
    type_domain_.Mutate(val.first, prng, metadata, only_shrink);
    val.second = GenericDomainCorpusType(std::in_place_type<void*>, nullptr);
    auto type_value = type_domain_.GetValue(val.first);
    if (type_value == 0 /* NONE */) {
      // NONE is a special value, it means that the union is not set.
      return;
    }
    auto type_enumval = union_def_->values()->LookupByKey(type_value);
    if (type_enumval == nullptr) {
      return;
    }

    // Deal with the value.
    const reflection::Object* object =
        schema_->objects()->Get(type_enumval->union_type()->index());
    if (object->is_struct()) {
      auto inner_val =
          GetSubDomain<FlatbuffersStructTag>(*type_enumval).Init(prng);
      val.second = std::move(inner_val);
    } else {
      auto inner_val =
          GetSubDomain<FlatbuffersTableTag>(*type_enumval).Init(prng);
      val.second = std::move(inner_val);
    }
  } else {
    // Keep the type, mutate the value.
    auto type_value = type_domain_.GetValue(val.first);
    auto type_enumval = union_def_->values()->LookupByKey(type_value);
    if (type_enumval == nullptr) {
      return;
    }
    const reflection::Object* object =
        schema_->objects()->Get(type_enumval->union_type()->index());
    if (object->is_struct()) {
      auto domain = GetSubDomain<FlatbuffersStructTag>(*type_enumval);
      domain.MutateSelectedField(val.second, prng, metadata, only_shrink,
                                 selected_weight - 1);
    } else {
      auto domain = GetSubDomain<FlatbuffersTableTag>(*type_enumval);
      domain.MutateSelectedField(val.second, prng, metadata, only_shrink,
                                 selected_weight - 1);
    }
  }
}

uint64_t FlatbuffersUnionDomainImpl::CountNumberOfFields(corpus_type& val) {
  // Unions are encoded as the combination of two fields: an enum representing
  // the union choice and the offset to the actual element.
  //
  // In turn, count starts with 1 to take care of the first field.
  uint64_t count = 1;
  auto type_value = type_domain_.GetValue(val.first);
  if (type_value == 0 /* NONE */) {
    // Union field is not set.
    return count;
  }
  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return count;
  }
  const reflection::Object* object =
      schema_->objects()->Get(type_enumval->union_type()->index());
  if (object->is_struct()) {
    auto domain = GetSubDomain<FlatbuffersStructTag>(*type_enumval);
    count += domain.CountNumberOfFields(val.second);
  } else {
    auto domain = GetSubDomain<FlatbuffersTableTag>(*type_enumval);
    count += domain.CountNumberOfFields(val.second);
  }
  return count;
}

absl::Status FlatbuffersUnionDomainImpl::ValidateCorpusValue(
    const corpus_type& corpus_value) const {
  // Unions are encoded as the combination of two fields: an enum representing
  // the union choice and the offset to the actual element.
  //
  // Both type and value should be validated.
  //
  // Start with the type validation.
  auto type_value = type_domain_.GetValue(corpus_value.first);
  if (type_value == 0 /* NONE */) {
    // Union field is not set.
    return absl::OkStatus();
  }
  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return absl::InvalidArgumentError(
        absl::StrCat("Invalid union type: ", type_value));
  }

  // Validate the value.
  if (!corpus_value.second.has_value()) {
    return absl::InvalidArgumentError("Union value is not set.");
  }
  const reflection::Object* object =
      schema_->objects()->Get(type_enumval->union_type()->index());
  if (object->is_struct()) {
    auto domain = GetSubDomain<FlatbuffersStructTag>(*type_enumval);
    return domain.ValidateCorpusValue(corpus_value.second);
  } else {
    auto domain = GetSubDomain<FlatbuffersTableTag>(*type_enumval);
    return domain.ValidateCorpusValue(corpus_value.second);
  }
}

// Converts the value to a corpus value.
std::optional<FlatbuffersUnionDomainImpl::corpus_type>
FlatbuffersUnionDomainImpl::FromValue(const value_type& value) const {
  auto out = std::make_optional<corpus_type>();
  auto type_value = type_domain_.FromValue(value.first);
  if (type_value.has_value()) {
    out->first = *type_value;
  }
  auto type_enumval = union_def_->values()->LookupByKey(value.first);
  if (type_enumval == nullptr) {
    return std::nullopt;
  }
  const reflection::Object* object =
      schema_->objects()->Get(type_enumval->union_type()->index());
  std::optional<CopyableAny> inner_corpus;
  if (object->is_struct()) {
    auto domain = GetSubDomain<FlatbuffersStructTag>(*type_enumval);
    inner_corpus =
        domain.FromValue(static_cast<const flatbuffers::Struct*>(value.second));
  } else {
    auto domain = GetSubDomain<FlatbuffersTableTag>(*type_enumval);
    inner_corpus =
        domain.FromValue(static_cast<const flatbuffers::Table*>(value.second));
  }
  if (inner_corpus.has_value()) {
    out->second = std::move(inner_corpus.value());
  }
  return out;
}

// Converts the IRObject to a corpus value.
std::optional<FlatbuffersUnionDomainImpl::corpus_type>
FlatbuffersUnionDomainImpl::ParseCorpus(const IRObject& obj) const {
  // Follows the structure created by `SerializeCorpus` to deserialize the
  // IRObject.
  corpus_type out;
  auto subs = obj.Subs();
  if (!subs) {
    return std::nullopt;
  }

  // We expect 2 fields: the type and the value.
  if (subs->size() != 2) {
    return std::nullopt;
  }

  // Parse the type which is stored in the first field of the IRObject subs.
  auto type_corpus = type_domain_.ParseCorpus((*subs)[0]);
  if (!type_corpus.has_value() ||
      !type_domain_.ValidateCorpusValue(*type_corpus).ok()) {
    return std::nullopt;
  }
  out.first = *type_corpus;
  auto type_value = type_domain_.GetValue(out.first);
  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return std::nullopt;
  }

  // Parse the value.
  const reflection::Object* object =
      schema_->objects()->Get(type_enumval->union_type()->index());
  if (object == nullptr) {
    return std::nullopt;
  }
  std::optional<CopyableAny> inner_corpus;
  if (object->is_struct()) {
    auto domain = GetSubDomain<FlatbuffersStructTag>(*type_enumval);
    // The value is stored in the second field of the IRObject subs.
    inner_corpus = domain.ParseCorpus((*subs)[1]);
  } else {
    auto domain = GetSubDomain<FlatbuffersTableTag>(*type_enumval);
    // The value is stored in the second field of the IRObject subs.
    inner_corpus = domain.ParseCorpus((*subs)[1]);
  }

  if (inner_corpus.has_value()) {
    out.second = std::move(inner_corpus.value());
  }
  return out;
}

// Converts the corpus value to an IRObject.
IRObject FlatbuffersUnionDomainImpl::SerializeCorpus(
    const corpus_type& value) const {
  IRObject out;
  auto type_value = type_domain_.GetValue(value.first);
  if (type_value == 0 /* NONE */) {
    return out;
  }

  auto& pair = out.MutableSubs();
  // We have 2 fields: the type and the value.
  pair.reserve(2);

  // Serialize the type.
  pair.push_back(type_domain_.SerializeCorpus(value.first));

  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return out;
  }

  // Serialize the value.
  const reflection::Object* object =
      schema_->objects()->Get(type_enumval->union_type()->index());
  if (object->is_struct()) {
    auto domain = GetSubDomain<FlatbuffersStructTag>(*type_enumval);
    pair.push_back(domain.SerializeCorpus(value.second));
  } else {
    auto domain = GetSubDomain<FlatbuffersTableTag>(*type_enumval);
    pair.push_back(domain.SerializeCorpus(value.second));
  }
  return out;
}

std::optional<flatbuffers::uoffset_t> FlatbuffersUnionDomainImpl::BuildValue(
    const corpus_type& value, flatbuffers::FlatBufferBuilder& builder) const {
  // Get the object type.
  auto type_value = type_domain_.GetValue(value.first);
  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr || type_value == 0 /* NONE */ ||
      !value.second.has_value()) {
    return std::nullopt;
  }
  const reflection::Object* object =
      schema_->objects()->Get(type_enumval->union_type()->index());
  if (object == nullptr) {
    return std::nullopt;
  }
  if (object->is_struct()) {
    FlatbuffersStructUntypedDomainImpl domain{schema_, object};
    return domain.BuildValue(
        value.second.GetAs<corpus_type_t<FlatbuffersStructUntypedDomainImpl>>(),
        builder);
  } else {
    FlatbuffersTableUntypedDomainImpl domain{schema_, object};
    return domain.BuildTable(
        value.second.GetAs<corpus_type_t<FlatbuffersTableUntypedDomainImpl>>(),
        builder);
  }
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
  if (type_value == 0 /* NONE */) {
    absl::Format(out, "NONE");
  } else {
    const reflection::Object* object =
        self.schema_->objects()->Get(type_enumval->union_type()->index());
    if (object->is_struct()) {
      auto domain = self.GetSubDomain<FlatbuffersStructTag>(*type_enumval);
      domain_implementor::PrintValue(domain, value.second, out, mode);
    } else {
      auto domain = self.GetSubDomain<FlatbuffersTableTag>(*type_enumval);
      domain_implementor::PrintValue(domain, value.second, out, mode);
    }
  }
  absl::Format(out, ")");
}

FlatbuffersStructUntypedDomainImpl::corpus_type
FlatbuffersStructUntypedDomainImpl::Init(absl::BitGenRef prng) {
  if (auto seed = this->MaybeGetRandomSeed(prng)) {
    return *seed;
  }
  corpus_type val;
  for (const auto* field : *struct_object_->fields()) {
    VisitFlatbufferField(schema_, field, InitializeVisitor{*this, prng, val});
  }
  return val;
}

void FlatbuffersStructUntypedDomainImpl::Mutate(
    corpus_type& val, absl::BitGenRef prng,
    const domain_implementor::MutationMetadata& metadata, bool only_shrink) {
  auto total_weight = CountNumberOfFields(val);
  auto selected_weight =
      absl::Uniform(absl::IntervalClosedClosed, prng, 0ul, total_weight - 1);

  MutateSelectedField(val, prng, metadata, only_shrink, selected_weight);
}

uint64_t FlatbuffersStructUntypedDomainImpl::CountNumberOfFields(
    corpus_type& val) {
  uint64_t total_weight = 0;
  for (const auto* field : *struct_object_->fields()) {
    VisitFlatbufferField(schema_, field,
                         CountNumberOfFieldsVisitor{*this, total_weight, val});
  }
  return total_weight;
}

// Mutates the selected field.
// The selected field index is based on the flattened tree.
uint64_t FlatbuffersStructUntypedDomainImpl::MutateSelectedField(
    corpus_type& val, absl::BitGenRef prng,
    const domain_implementor::MutationMetadata& metadata, bool only_shrink,
    uint64_t selected_field_index) {
  uint64_t field_counter = 0;
  for (const auto* field : *struct_object_->fields()) {
    ++field_counter;

    if (field_counter == selected_field_index + 1) {
      VisitFlatbufferField(
          schema_, field,
          MutateVisitor{*this, prng, metadata, only_shrink, val});
      return field_counter;
    }

    auto base_type = field->type()->base_type();
    if (base_type == reflection::BaseType::Obj) {
      auto sub_object = schema_->objects()->Get(field->type()->index());
      if (sub_object->is_struct()) {
        field_counter +=
            GetSubDomain<FlatbuffersStructTag>(field).MutateSelectedField(
                val[field->id()], prng, metadata, only_shrink,
                selected_field_index - field_counter);
      }
    }

    if (field_counter > selected_field_index) {
      return field_counter;
    }
  }
  return field_counter;
}

absl::Status FlatbuffersStructUntypedDomainImpl::ValidateCorpusValue(
    const corpus_type& corpus_value) const {
  for (const auto& [id, field_corpus] : corpus_value) {
    const reflection::Field* absl_nullable field = GetFieldById(id);
    if (field == nullptr) continue;
    absl::Status result;
    VisitFlatbufferField(schema_, field,
                         ValidateVisitor{*this, field_corpus, result});
    if (!result.ok()) return result;
  }
  return absl::OkStatus();
}

std::optional<FlatbuffersStructUntypedDomainImpl::corpus_type>
FlatbuffersStructUntypedDomainImpl::FromValue(const value_type& value) const {
  if (value == nullptr) {
    return std::nullopt;
  }
  corpus_type ret;
  for (const auto* field : *struct_object_->fields()) {
    VisitFlatbufferField(schema_, field, FromValueVisitor{*this, value, ret});
  }
  return ret;
}

std::optional<flatbuffers::uoffset_t>
FlatbuffersStructUntypedDomainImpl::BuildValue(
    const corpus_type& value, flatbuffers::FlatBufferBuilder& builder) const {
  std::vector<uint8_t> buf(struct_object_->bytesize());
  BuildValue(value, buf.data());
  builder.StartStruct(struct_object_->minalign());
  builder.PushBytes(buf.data(), buf.size());
  return builder.EndStruct();
}

void FlatbuffersStructUntypedDomainImpl::BuildValue(const corpus_type& value,
                                                    uint8_t* buf) const {
  for (const auto* field : *struct_object_->fields()) {
    VisitFlatbufferField(schema_, field, BuildValueVisitor{*this, value, buf});
  }
}

std::optional<FlatbuffersStructUntypedDomainImpl::corpus_type>
FlatbuffersStructUntypedDomainImpl::ParseCorpus(const IRObject& obj) const {
  corpus_type out;
  auto subs = obj.Subs();
  if (!subs) {
    return std::nullopt;
  }
  out.reserve(subs->size());
  for (const auto& sub : *subs) {
    auto pair_subs = sub.Subs();
    if (!pair_subs || pair_subs->size() != 2) {
      return std::nullopt;
    }
    auto id = (*pair_subs)[0].GetScalar<typename corpus_type::key_type>();
    if (!id.has_value()) {
      return std::nullopt;
    }
    const reflection::Field* absl_nullable field = GetFieldById(id.value());
    if (field == nullptr) {
      return std::nullopt;
    }
    std::optional<GenericDomainCorpusType> inner_parsed;
    VisitFlatbufferField(schema_, field,
                         ParseVisitor{*this, (*pair_subs)[1], inner_parsed});
    if (!inner_parsed) {
      return std::nullopt;
    }
    out[id.value()] = *std::move(inner_parsed);
  }
  return out;
}

// Converts the corpus value to an IRObject.
IRObject FlatbuffersStructUntypedDomainImpl::SerializeCorpus(
    const corpus_type& value) const {
  IRObject out;
  auto& subs = out.MutableSubs();
  subs.reserve(value.size());
  for (const auto& [id, field_corpus] : value) {
    const reflection::Field* absl_nullable field = GetFieldById(id);
    if (field == nullptr) {
      continue;
    }
    IRObject& pair = subs.emplace_back();
    auto& pair_subs = pair.MutableSubs();
    pair_subs.reserve(2);
    pair_subs.emplace_back(field->id());
    VisitFlatbufferField(
        schema_, field,
        SerializeVisitor{*this, field_corpus, pair_subs.emplace_back()});
  }
  return out;
}
}  // namespace internal
}  // namespace fuzztest
