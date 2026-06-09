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
#include "absl/container/flat_hash_map.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/synchronization/mutex.h"
#include "flatbuffers/base.h"
#include "flatbuffers/flatbuffer_builder.h"
#include "flatbuffers/reflection_generated.h"
#include "flatbuffers/struct.h"
#include "flatbuffers/table.h"
#include "./common/logging.h"
#include "./fuzztest/domain_core.h"
#include "./fuzztest/internal/any.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"

namespace fuzztest::internal {

// Gets a domain for a specific struct type.
template <>
auto FlatbuffersUnionDomainImpl::GetDefaultDomainForType<FlatbuffersStructTag>(
    const reflection::EnumVal& enum_value) const {
  const reflection::Object* object =
      schema_->objects()->Get(enum_value.union_type()->index());
  return Domain<const flatbuffers::Struct*>(
      FlatbuffersStructUntypedDomainImpl{schema_, object});
}

FlatbuffersUnionDomainImpl::FlatbuffersUnionDomainImpl(
    const reflection::Schema* schema, const reflection::Enum* union_def)
    : schema_(schema), union_def_(union_def), type_domain_(union_def) {
  type_domain_.WithExcludedValues({0 /* NONE */});
}

FlatbuffersUnionDomainImpl::FlatbuffersUnionDomainImpl(
    const FlatbuffersUnionDomainImpl& other)
    : schema_(other.schema_),
      union_def_(other.union_def_),
      type_domain_(other.type_domain_) {
  absl::MutexLock l(mutex_);
  absl::MutexLock l_other(other.mutex_);
  domains_ = other.domains_;
}

FlatbuffersUnionDomainImpl::FlatbuffersUnionDomainImpl(
    FlatbuffersUnionDomainImpl&& other)
    : schema_(other.schema_),
      union_def_(other.union_def_),
      type_domain_(std::move(other.type_domain_)) {
  absl::MutexLock l(mutex_);
  absl::MutexLock l_other(other.mutex_);
  domains_ = std::move(other.domains_);
}

// Get a domain for a specific table type.
template <>
auto FlatbuffersUnionDomainImpl::GetDefaultDomainForType<FlatbuffersTableTag>(
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

  val.type = type_domain_.Init(prng);
  auto type_value = type_domain_.GetValue(val.type);

  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return val;
  }

  const reflection::Object* object =
      schema_->objects()->Get(type_enumval->union_type()->index());
  if (object->is_struct()) {
    auto inner_val =
        GetCachedDomain<FlatbuffersStructTag>(*type_enumval).Init(prng);
    val.value = std::move(inner_val);
  } else {
    auto inner_val =
        GetCachedDomain<FlatbuffersTableTag>(*type_enumval).Init(prng);
    val.value = std::move(inner_val);
  }
  return val;
}

// Mutates the corpus value.
void FlatbuffersUnionDomainImpl::Mutate(
    corpus_type& corpus_value, absl::BitGenRef prng,
    const domain_implementor::MutationMetadata& metadata, bool only_shrink) {
  auto type_value = type_domain_.GetValue(corpus_value.type);

  // Mutate the type with probability 1%.
  if (absl::Bernoulli(prng, 0.01)) {
    // Mutate the type.
    type_domain_.Mutate(corpus_value.type, prng, metadata, only_shrink);
    type_value = type_domain_.GetValue(corpus_value.type);

    // If the union is set after type mutation, init the value corpus value.
    auto type_enumval = union_def_->values()->LookupByKey(type_value);
    if (type_enumval == nullptr) return;

    const reflection::Object* object =
        schema_->objects()->Get(type_enumval->union_type()->index());
    if (object->is_struct()) {
      corpus_value.value =
          GetCachedDomain<FlatbuffersStructTag>(*type_enumval).Init(prng);
    } else {
      corpus_value.value =
          GetCachedDomain<FlatbuffersTableTag>(*type_enumval).Init(prng);
    }
    return;
  }

  // Mutate the value if the union is set.
  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) return;

  const reflection::Object* object =
      schema_->objects()->Get(type_enumval->union_type()->index());
  if (object->is_struct()) {
    auto domain = GetCachedDomain<FlatbuffersStructTag>(*type_enumval);
    domain.Mutate(corpus_value.value, prng, metadata, only_shrink);
  } else {
    GetCachedDomain<FlatbuffersTableTag>(*type_enumval)
        .Mutate(corpus_value.value, prng, metadata, only_shrink);
  }
}

uint64_t FlatbuffersUnionDomainImpl::CountNumberOfFields(
    corpus_type& corpus_value) {
  uint64_t field_count = 0;

  // If the union has only one type (besides NONE), the type is not counted
  // as mutable field.
  if (union_def_->values()->size() <= 2) {
    return field_count;
  }

  // The first field is the union type.
  ++field_count;

  auto type_value = type_domain_.GetValue(corpus_value.type);
  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return field_count;
  }
  const reflection::Object* object =
      schema_->objects()->Get(type_enumval->union_type()->index());
  if (object->is_struct()) {
    auto domain = GetCachedDomain<FlatbuffersStructTag>(*type_enumval);
    field_count += domain.CountNumberOfFields(corpus_value.value);
  } else {
    auto domain = GetCachedDomain<FlatbuffersTableTag>(*type_enumval);
    field_count += domain.CountNumberOfFields(corpus_value.value);
  }
  return field_count;
}

uint64_t FlatbuffersUnionDomainImpl::MutateSelectedField(
    corpus_type& corpus_value, absl::BitGenRef prng,
    const domain_implementor::MutationMetadata& metadata, bool only_shrink,
    uint64_t selected_field_index) {
  uint64_t field_count = 0;

  // If the union has only one type (besides NONE), the type is not counted
  // as mutable field.
  if (union_def_->values()->size() <= 2) {
    return field_count;
  }

  // The first field is the union type.
  ++field_count;
  if (selected_field_index == field_count) {
    type_domain_.Mutate(corpus_value.type, prng, metadata, only_shrink);
    auto type_value = type_domain_.GetValue(corpus_value.type);
    auto type_enumval = union_def_->values()->LookupByKey(type_value);
    if (type_enumval == nullptr) return selected_field_index;

    const reflection::Object* object =
        schema_->objects()->Get(type_enumval->union_type()->index());
    if (object->is_struct()) {
      corpus_value.value =
          GetCachedDomain<FlatbuffersStructTag>(*type_enumval).Init(prng);
    } else {
      corpus_value.value =
          GetCachedDomain<FlatbuffersTableTag>(*type_enumval).Init(prng);
    }
    return field_count;
  }

  auto type_value = type_domain_.GetValue(corpus_value.type);

  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return 0;
  }
  const reflection::Object* object =
      schema_->objects()->Get(type_enumval->union_type()->index());
  if (object->is_struct()) {
    auto domain = GetCachedDomain<FlatbuffersStructTag>(*type_enumval);
    field_count += domain.MutateSelectedField(
        corpus_value.value, prng, metadata, only_shrink,
        selected_field_index - field_count);
  } else {
    auto domain = GetCachedDomain<FlatbuffersTableTag>(*type_enumval);
    field_count += domain.MutateSelectedField(
        corpus_value.value, prng, metadata, only_shrink,
        selected_field_index - field_count);
  }
  return field_count;
}

absl::Status FlatbuffersUnionDomainImpl::ValidateCorpusValue(
    const corpus_type& corpus_value) const {
  // Unions are encoded as the combination of two fields: an enum representing
  // the union choice and the offset to the actual element.
  //
  // Both type and value should be validated.
  //
  // Start with the type validation.
  auto type_value = type_domain_.GetValue(corpus_value.type);

  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return absl::InvalidArgumentError(
        absl::StrCat("Invalid union type: ", type_value));
  }

  // Validate the value.
  if (!corpus_value.value.has_value()) {
    return absl::InvalidArgumentError("Union value is not set.");
  }
  const reflection::Object* object =
      schema_->objects()->Get(type_enumval->union_type()->index());
  if (object->is_struct()) {
    auto domain = GetCachedDomain<FlatbuffersStructTag>(*type_enumval);
    return domain.ValidateCorpusValue(corpus_value.value);
  } else {
    auto domain = GetCachedDomain<FlatbuffersTableTag>(*type_enumval);
    return domain.ValidateCorpusValue(corpus_value.value);
  }
}

// Converts the value to a corpus value.
std::optional<FlatbuffersUnionDomainImpl::corpus_type>
FlatbuffersUnionDomainImpl::FromValue(const value_type& value) const {
  auto out = std::make_optional<corpus_type>();
  auto type_corpus = type_domain_.FromValue(value.type);
  if (type_corpus.has_value()) {
    out->type = *type_corpus;
  }
  auto type_enumval = union_def_->values()->LookupByKey(value.type);
  if (type_enumval == nullptr) {
    return std::nullopt;
  }
  const reflection::Object* object =
      schema_->objects()->Get(type_enumval->union_type()->index());
  std::optional<CopyableAny> inner_corpus;
  if (object->is_struct()) {
    auto domain = GetCachedDomain<FlatbuffersStructTag>(*type_enumval);
    inner_corpus =
        domain.FromValue(static_cast<const flatbuffers::Struct*>(value.value));
  } else {
    auto domain = GetCachedDomain<FlatbuffersTableTag>(*type_enumval);
    inner_corpus =
        domain.FromValue(static_cast<const flatbuffers::Table*>(value.value));
  }
  if (inner_corpus.has_value()) {
    out->value = std::move(inner_corpus.value());
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
  if (!type_corpus.has_value()) {
    return std::nullopt;
  }
  if (auto status = type_domain_.ValidateCorpusValue(*type_corpus);
      !status.ok()) {
    FUZZTEST_LOG(ERROR) << "Failed to validate type corpus: "
                        << status.message();
    return std::nullopt;
  }
  out.type = *type_corpus;
  auto type_value = type_domain_.GetValue(out.type);
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
    auto domain = GetCachedDomain<FlatbuffersStructTag>(*type_enumval);
    // The value is stored in the second field of the IRObject subs.
    inner_corpus = domain.ParseCorpus((*subs)[1]);
  } else {
    auto domain = GetCachedDomain<FlatbuffersTableTag>(*type_enumval);
    // The value is stored in the second field of the IRObject subs.
    inner_corpus = domain.ParseCorpus((*subs)[1]);
  }

  if (inner_corpus.has_value()) {
    out.value = std::move(inner_corpus.value());
  }
  return out;
}

// Converts the corpus value to an IRObject.
IRObject FlatbuffersUnionDomainImpl::SerializeCorpus(
    const corpus_type& corpus_value) const {
  IRObject out;
  auto type_value = type_domain_.GetValue(corpus_value.type);

  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return out;
  }

  auto& pair = out.MutableSubs();
  // We have 2 fields: the type and the value.
  pair.reserve(2);

  // Serialize the type.
  pair.push_back(type_domain_.SerializeCorpus(corpus_value.type));

  // Serialize the value.
  const reflection::Object* object =
      schema_->objects()->Get(type_enumval->union_type()->index());
  if (object->is_struct()) {
    auto domain = GetCachedDomain<FlatbuffersStructTag>(*type_enumval);
    pair.push_back(domain.SerializeCorpus(corpus_value.value));
  } else {
    auto domain = GetCachedDomain<FlatbuffersTableTag>(*type_enumval);
    pair.push_back(domain.SerializeCorpus(corpus_value.value));
  }
  return out;
}

std::optional<flatbuffers::uoffset_t> FlatbuffersUnionDomainImpl::BuildValue(
    const corpus_type& corpus_value,
    flatbuffers::FlatBufferBuilder64& builder) const {
  // Get the object type.
  auto type_value = type_domain_.GetValue(corpus_value.type);
  auto type_enumval = union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr || !corpus_value.value.has_value()) {
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
        corpus_value.value
            .GetAs<corpus_type_t<FlatbuffersStructUntypedDomainImpl>>(),
        builder);
  } else {
    FlatbuffersTableUntypedDomainImpl domain{schema_, object};
    return domain.BuildTable(
        corpus_value.value
            .GetAs<corpus_type_t<FlatbuffersTableUntypedDomainImpl>>(),
        builder);
  }
}

void FlatbuffersUnionDomainImpl::Printer::PrintCorpusValue(
    const corpus_type& value, domain_implementor::RawSink out,
    domain_implementor::PrintMode mode) const {
  auto type_value = self.type_domain_.GetValue(value.type);
  auto type_enumval = self.union_def_->values()->LookupByKey(type_value);
  if (type_enumval == nullptr) {
    return;
  }
  absl::Format(out, "<%s>(", type_enumval->name()->str());

  const reflection::Object* object =
      self.schema_->objects()->Get(type_enumval->union_type()->index());
  if (object->is_struct()) {
    auto domain = self.GetCachedDomain<FlatbuffersStructTag>(*type_enumval);
    domain_implementor::PrintValue(domain, value.value, out, mode);
  } else {
    auto domain = self.GetCachedDomain<FlatbuffersTableTag>(*type_enumval);
    domain_implementor::PrintValue(domain, value.value, out, mode);
  }
  absl::Format(out, ")");
}

std::optional<FlatbuffersStructUntypedDomainImpl::corpus_type>
FlatbuffersStructUntypedDomainImpl::FromValue(const value_type& value) const {
  if (value == nullptr) {
    return std::nullopt;
  }
  corpus_type val;
  for (const auto& [_, field] : fields_by_id_) {
    VisitFlatbufferField(schema_, field, FromValueVisitor{*this, value, val});
  }
  return val;
}

std::optional<flatbuffers::uoffset_t>
FlatbuffersStructUntypedDomainImpl::BuildValue(
    const corpus_type& value, flatbuffers::FlatBufferBuilder64& builder) const {
  std::vector<uint8_t> buf(object_->bytesize());
  BuildValue(value, buf.data());
  builder.StartStruct(object_->minalign());
  builder.PushBytes(buf.data(), buf.size());
  return builder.EndStruct();
}

void FlatbuffersStructUntypedDomainImpl::BuildValue(const corpus_type& value,
                                                    uint8_t* buf) const {
  for (const auto& [_, field] : fields_by_id_) {
    VisitFlatbufferField(schema_, field, BuildValueVisitor{*this, value, buf});
  }
}

std::optional<FlatbuffersTableUntypedDomainImpl::corpus_type>
FlatbuffersTableUntypedDomainImpl::FromValue(const value_type& value) const {
  if (value == nullptr) {
    return std::nullopt;
  }
  corpus_type ret;
  for (const auto& [_, field] : fields_by_id_) {
    VisitFlatbufferField(schema_, field, FromValueVisitor{*this, value, ret});
  }
  return ret;
}

uint32_t FlatbuffersTableUntypedDomainImpl::BuildTable(
    const corpus_type& value, flatbuffers::FlatBufferBuilder64& builder) const {
  // Add all the fields to the builder.

  // Offsets is the map of field id to its offset in the table.
  absl::flat_hash_map<typename corpus_type::key_type, flatbuffers::uoffset64_t>
      offsets;

  // Some fields are stored inline in the flatbuffer table itself (a.k.a
  // "inline fields") and some are referenced by their offsets (a.k.a. "out of
  // line fields").
  //
  // "Out of line fields" shall be added to the builder first, so that we can
  // refer to them in the final table.
  for (const auto& [id, field_corpus] : value) {
    const reflection::Field* absl_nullable field = GetFieldById(id);
    if (field == nullptr) {
      continue;
    }
    // Take care of strings, and tables.
    VisitFlatbufferField(
        schema_, field,
        TableFieldBuilderVisitor{*this, builder, offsets, field_corpus});
  }

  // Now it is time to build the final table.
  uint32_t table_start = builder.StartTable();
  for (const auto& [id, field_corpus] : value) {
    const reflection::Field* absl_nullable field = GetFieldById(id);
    if (field == nullptr) {
      continue;
    }

    // Visit all fields.
    //
    // Inline fields will be stored in the table itself, out of line fields
    // will be referenced by their offsets.
    VisitFlatbufferField(
        schema_, field,
        TableBuilderVisitor{*this, builder, offsets, field_corpus});
  }
  return builder.EndTable(table_start);
}

}  // namespace fuzztest::internal
