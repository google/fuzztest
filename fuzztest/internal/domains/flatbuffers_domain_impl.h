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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FLATBUFFERS_DOMAIN_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FLATBUFFERS_DOMAIN_IMPL_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <list>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/base/nullability.h"
#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/synchronization/mutex.h"
#include "flatbuffers/base.h"
#include "flatbuffers/flatbuffer_builder.h"
#include "flatbuffers/reflection.h"
#include "flatbuffers/reflection_generated.h"
#include "flatbuffers/string.h"
#include "flatbuffers/struct.h"
#include "flatbuffers/table.h"
#include "flatbuffers/vector.h"
#include "flatbuffers/verifier.h"
#include "./fuzztest/domain_core.h"
#include "./fuzztest/internal/any.h"
#include "./fuzztest/internal/domains/arbitrary_impl.h"
#include "./fuzztest/internal/domains/container_of_impl.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/domain_type_erasure.h"
#include "./fuzztest/internal/domains/element_of_impl.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/status.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

//
// Flatbuffers enum detection.
//
template <typename Underlying,
          typename = std::enable_if_t<std::is_integral_v<Underlying> &&
                                      !std::is_same_v<Underlying, bool>>>
struct FlatbuffersEnumTag {
  using type = Underlying;
};

template <typename T>
struct is_flatbuffers_enum_tag : std::false_type {};

template <typename Underlying, typename Enable>
struct is_flatbuffers_enum_tag<FlatbuffersEnumTag<Underlying, Enable>>
    : std::true_type {};

template <typename T>
inline constexpr bool is_flatbuffers_enum_tag_v =
    is_flatbuffers_enum_tag<T>::value;

//
// Flatbuffers vector detection.
//
template <typename T>
struct FlatbuffersVectorTag {
  using value_type = T;
};

template <typename T>
struct is_flatbuffers_vector_tag : std::false_type {};

template <typename T>
struct is_flatbuffers_vector_tag<FlatbuffersVectorTag<T>> : std::true_type {};

template <typename T>
inline constexpr bool is_flatbuffers_vector_tag_v =
    is_flatbuffers_vector_tag<T>::value;

//
// Flatbuffers array detection.
//
template <typename T>
struct FlatbuffersArrayTag {
  using value_type = T;
};

template <typename T>
struct is_flatbuffers_array_tag : std::false_type {};

template <typename T>
struct is_flatbuffers_array_tag<FlatbuffersArrayTag<T>> : std::true_type {};

template <typename T>
inline constexpr bool is_flatbuffers_array_tag_v =
    is_flatbuffers_array_tag<T>::value;

struct FlatbuffersTableTag;
struct FlatbuffersStructTag;
struct FlatbuffersUnionTag;

// Dynamic to static dispatch visitor pattern for flatbuffers container
// elements.
template <template <typename> typename ContainerTag, typename Visitor>
auto VisitFlatbufferContainerElementField(const reflection::Schema* schema,
                                          const reflection::Field* field,
                                          Visitor visitor) {
  auto field_index = field->type()->index();
  auto element_type = field->type()->element();
  switch (element_type) {
    case reflection::BaseType::Bool:
      visitor.template Visit<ContainerTag<bool>>(field);
      break;
    case reflection::BaseType::Byte:
      if (field_index >= 0) {
        visitor.template Visit<ContainerTag<FlatbuffersEnumTag<int8_t>>>(field);
      } else {
        visitor.template Visit<ContainerTag<int8_t>>(field);
      }
      break;
    case reflection::BaseType::Short:
      if (field_index >= 0) {
        visitor.template Visit<ContainerTag<FlatbuffersEnumTag<int16_t>>>(
            field);
      } else {
        visitor.template Visit<ContainerTag<int16_t>>(field);
      }
      break;
    case reflection::BaseType::Int:
      if (field_index >= 0) {
        visitor.template Visit<ContainerTag<FlatbuffersEnumTag<int32_t>>>(
            field);
      } else {
        visitor.template Visit<ContainerTag<int32_t>>(field);
      }
      break;
    case reflection::BaseType::Long:
      if (field_index >= 0) {
        visitor.template Visit<ContainerTag<FlatbuffersEnumTag<int64_t>>>(
            field);
      } else {
        visitor.template Visit<ContainerTag<int64_t>>(field);
      }
      break;
    case reflection::BaseType::UByte:
      if (field_index >= 0) {
        visitor.template Visit<ContainerTag<FlatbuffersEnumTag<uint8_t>>>(
            field);
      } else {
        visitor.template Visit<ContainerTag<uint8_t>>(field);
      }
      break;
    case reflection::BaseType::UShort:
      if (field_index >= 0) {
        visitor.template Visit<ContainerTag<FlatbuffersEnumTag<uint16_t>>>(
            field);
      } else {
        visitor.template Visit<ContainerTag<uint16_t>>(field);
      }
      break;
    case reflection::BaseType::UInt:
      if (field_index >= 0) {
        visitor.template Visit<ContainerTag<FlatbuffersEnumTag<uint32_t>>>(
            field);
      } else {
        visitor.template Visit<ContainerTag<uint32_t>>(field);
      }
      break;
    case reflection::BaseType::ULong:
      if (field_index >= 0) {
        visitor.template Visit<ContainerTag<FlatbuffersEnumTag<uint64_t>>>(
            field);
      } else {
        visitor.template Visit<ContainerTag<uint64_t>>(field);
      }
      break;
    case reflection::BaseType::Float:
      visitor.template Visit<ContainerTag<float>>(field);
      break;
    case reflection::BaseType::Double:
      visitor.template Visit<ContainerTag<double>>(field);
      break;
    case reflection::BaseType::String:
      if constexpr (is_flatbuffers_vector_tag_v<ContainerTag<std::string>>) {
        visitor.template Visit<ContainerTag<std::string>>(field);
      } else if constexpr (is_flatbuffers_array_tag_v<
                               ContainerTag<std::string>>) {
        FUZZTEST_INTERNAL_CHECK(false,
                                "Strings are not supported as array elements");
      }
      break;
    case reflection::BaseType::Obj: {
      auto sub_object = schema->objects()->Get(field_index);
      if (sub_object->is_struct()) {
        visitor.template Visit<ContainerTag<FlatbuffersStructTag>>(field);
      } else if constexpr (is_flatbuffers_vector_tag_v<
                               ContainerTag<FlatbuffersTableTag>>) {
        visitor.template Visit<ContainerTag<FlatbuffersTableTag>>(field);
      } else if constexpr (is_flatbuffers_array_tag_v<
                               ContainerTag<FlatbuffersTableTag>>) {
        FUZZTEST_INTERNAL_CHECK(false,
                                "Tables are not supported as array elements");
      }
      break;
    }
    case reflection::BaseType::Union:
      if constexpr (is_flatbuffers_vector_tag_v<
                        ContainerTag<FlatbuffersUnionTag>>) {
        visitor.template Visit<ContainerTag<FlatbuffersUnionTag>>(field);
      } else if constexpr (is_flatbuffers_array_tag_v<
                               ContainerTag<FlatbuffersUnionTag>>) {
        FUZZTEST_INTERNAL_CHECK(false,
                                "Unions are not supported as array elements");
      }
      break;
    case reflection::BaseType::UType:
      // Noop: Union types are visited at the same time as their corresponding
      // union values.
      break;
    default:
      FUZZTEST_INTERNAL_CHECK(false, "Unsupported container element type");
  }
}

// Dynamic to static dispatch visitor pattern.
template <typename Visitor>
auto VisitFlatbufferField(const reflection::Schema* absl_nonnull schema,
                          const reflection::Field* absl_nonnull field,
                          Visitor visitor) {
  auto field_index = field->type()->index();
  switch (field->type()->base_type()) {
    case reflection::BaseType::Bool:
      visitor.template Visit<bool>(field);
      break;
    case reflection::BaseType::Byte:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<int8_t>>(field);
      } else {
        visitor.template Visit<int8_t>(field);
      }
      break;
    case reflection::BaseType::Short:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<int16_t>>(field);
      } else {
        visitor.template Visit<int16_t>(field);
      }
      break;
    case reflection::BaseType::Int:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<int32_t>>(field);
      } else {
        visitor.template Visit<int32_t>(field);
      }
      break;
    case reflection::BaseType::Long:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<int64_t>>(field);
      } else {
        visitor.template Visit<int64_t>(field);
      }
      break;
    case reflection::BaseType::UByte:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<uint8_t>>(field);
      } else {
        visitor.template Visit<uint8_t>(field);
      }
      break;
    case reflection::BaseType::UShort:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<uint16_t>>(field);
      } else {
        visitor.template Visit<uint16_t>(field);
      }
      break;
    case reflection::BaseType::UInt:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<uint32_t>>(field);
      } else {
        visitor.template Visit<uint32_t>(field);
      }
      break;
    case reflection::BaseType::ULong:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<uint64_t>>(field);
      } else {
        visitor.template Visit<uint64_t>(field);
      }
      break;
    case reflection::BaseType::Float:
      visitor.template Visit<float>(field);
      break;
    case reflection::BaseType::Double:
      visitor.template Visit<double>(field);
      break;
    case reflection::BaseType::String:
      visitor.template Visit<std::string>(field);
      break;
    case reflection::BaseType::Vector:
    case reflection::BaseType::Vector64:
      VisitFlatbufferContainerElementField<FlatbuffersVectorTag, Visitor>(
          schema, field, visitor);
      break;
    case reflection::BaseType::Array:
      VisitFlatbufferContainerElementField<FlatbuffersArrayTag, Visitor>(
          schema, field, visitor);
      break;
    case reflection::BaseType::Obj: {
      auto sub_object = schema->objects()->Get(field->type()->index());
      if (sub_object->is_struct()) {
        visitor.template Visit<FlatbuffersStructTag>(field);
      } else {
        visitor.template Visit<FlatbuffersTableTag>(field);
      }
      break;
    }
    case reflection::BaseType::Union:
      visitor.template Visit<FlatbuffersUnionTag>(field);
      break;
    case reflection::BaseType::UType:
      // Noop: Union types are visited at the same time as their corresponding
      // union values.
      break;
    default:
      FUZZTEST_INTERNAL_CHECK(false, absl::StrCat("Unsupported base type: ",
                                                  field->type()->base_type()));
  }
}

// Forward declaration of the domain factory for flatbuffers fields.
template <typename T>
auto GetDefaultDomain(const reflection::Schema* absl_nonnull schema,
                      const reflection::Field* absl_nonnull field);

// Flatbuffers enum domain implementation.
template <typename Underlaying>
class FlatbuffersEnumDomainImpl
    : public domain_implementor::DomainBase<
          /*Derived=*/FlatbuffersEnumDomainImpl<Underlaying>,
          /*ValueType=*/Underlaying,
          /*CorpusType=*/ElementOfImplCorpusType> {
 public:
  using typename FlatbuffersEnumDomainImpl::DomainBase::corpus_type;
  using typename FlatbuffersEnumDomainImpl::DomainBase::value_type;

  explicit FlatbuffersEnumDomainImpl(const reflection::Enum* enum_def)
      : enum_def_(enum_def), inner_(GetEnumValues(enum_def)) {}

  corpus_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    return inner_.Init(prng);
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng,
              const domain_implementor::MutationMetadata& metadata,
              bool only_shrink) {
    inner_.Mutate(val, prng, metadata, only_shrink);
  }

  value_type GetValue(corpus_type value) const {
    return inner_.GetValue(value);
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    return inner_.FromValue(v);
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    return inner_.ParseCorpus(obj);
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return inner_.SerializeCorpus(v);
  }

  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const {
    return inner_.ValidateCorpusValue(corpus_value);
  }

  auto GetPrinter() const { return Printer{*this}; }

 private:
  const reflection::Enum* enum_def_;
  ElementOfImpl<Underlaying> inner_;

  static std::vector<value_type> GetEnumValues(
      const reflection::Enum* enum_def) {
    std::vector<value_type> values;
    values.reserve(enum_def->values()->size());
    for (const auto* value : *enum_def->values()) {
      FUZZTEST_INTERNAL_CHECK(
          value->value() >= std::numeric_limits<value_type>::min() &&
              value->value() <= std::numeric_limits<value_type>::max(),
          "Enum value from reflection is out of range for the target type.");
      values.push_back(static_cast<value_type>(value->value()));
    }
    return values;
  }

  struct Printer {
    const FlatbuffersEnumDomainImpl& self;
    void PrintCorpusValue(const corpus_type& value,
                          domain_implementor::RawSink out,
                          domain_implementor::PrintMode mode) const {
      if (mode == domain_implementor::PrintMode::kHumanReadable) {
        auto user_value = self.GetValue(value);
        absl::Format(
            out, "%s",
            self.enum_def_->values()->LookupByKey(user_value)->name()->str());
      } else {
        absl::Format(out, "%d", value);
      }
    }
  };
};

// Forward declaration of the domain factory for flatbuffers fields.
template <typename T>
auto GetDefaultDomain(const reflection::Schema* absl_nonnull schema,
                      const reflection::Field* absl_nonnull field);

// From flatbuffers documentation:
// Unions are encoded as the combination of two fields: an enum representing the
// union choice and the offset to the actual element.
// The type of the enum is always uint8_t as generated by the flatbuffers
// compiler.
using FlatbuffersUnionTypeDomainImpl = FlatbuffersEnumDomainImpl<uint8_t>;

// Base class for flatbuffers struct and table domain implementations.
// The corpus type is a map of field ids to field values.
template <typename Derived, typename ValueType>
class FlatbuffersUntypedObjectDomainBase
    : public domain_implementor::DomainBase<
          /*Derived=*/Derived,
          /*ValueType=*/ValueType,
          /*CorpusType=*/
          absl::flat_hash_map<
              decltype(static_cast<reflection::Field*>(nullptr)->id()),
              GenericDomainCorpusType>> {
 public:
  using DomainBase = domain_implementor::DomainBase<
      Derived, ValueType,
      absl::flat_hash_map<
          decltype(static_cast<reflection::Field*>(nullptr)->id()),
          GenericDomainCorpusType>>;
  using typename FlatbuffersUntypedObjectDomainBase::DomainBase::corpus_type;
  using typename FlatbuffersUntypedObjectDomainBase::DomainBase::value_type;

  FlatbuffersUntypedObjectDomainBase(
      const reflection::Schema* absl_nonnull schema,
      const reflection::Object* absl_nonnull object)
      : schema_(schema), object_(object) {}

  virtual ~FlatbuffersUntypedObjectDomainBase() = default;

  FlatbuffersUntypedObjectDomainBase(
      const FlatbuffersUntypedObjectDomainBase& other)
      : DomainBase(other), schema_(other.schema_), object_(other.object_) {
    absl::MutexLock l(&mutex_);
    absl::MutexLock l_other(&other.mutex_);
    domains_ = other.domains_;
  }

  FlatbuffersUntypedObjectDomainBase& operator=(
      const FlatbuffersUntypedObjectDomainBase& other) {
    DomainBase::operator=(other);
    schema_ = other.schema_;
    object_ = other.object_;
    absl::MutexLock l(&mutex_);
    absl::MutexLock l_other(&other.mutex_);
    domains_ = other.domains_;
    return *this;
  }

  FlatbuffersUntypedObjectDomainBase(FlatbuffersUntypedObjectDomainBase&& other)
      : DomainBase(std::move(other)),
        schema_(other.schema_),
        object_(other.object_) {
    absl::MutexLock l(&mutex_);
    absl::MutexLock l_other(&other.mutex_);
    domains_ = std::move(other.domains_);
  }

  FlatbuffersUntypedObjectDomainBase& operator=(
      FlatbuffersUntypedObjectDomainBase&& other) {
    DomainBase::operator=(std::move(other));
    schema_ = other.schema_;
    object_ = other.object_;
    absl::MutexLock l(&mutex_);
    absl::MutexLock l_other(&other.mutex_);
    domains_ = std::move(other.domains_);
    return *this;
  }

  // Initializes the corpus value.
  corpus_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) {
      return *seed;
    }
    corpus_type val;
    for (const auto* field : *object_->fields()) {
      VisitFlatbufferField(schema_, field, InitializeVisitor{*this, prng, val});
    }
    return val;
  }

  // Mutates the corpus value.
  void Mutate(corpus_type& val, absl::BitGenRef prng,
              const domain_implementor::MutationMetadata& metadata,
              bool only_shrink) {
    auto field_count = CountNumberOfFields(val);
    auto selected_field_index = absl::Uniform(prng, 0ul, field_count);

    MutateSelectedField(val, prng, metadata, only_shrink, selected_field_index);
  }

  // Counts the number of fields that can be mutated.
  // Returns the number of fields in the flattened tree for supported field
  // types.
  uint64_t CountNumberOfFields(corpus_type& val) {
    uint64_t field_count = 0;
    for (const auto* field : *object_->fields()) {
      VisitFlatbufferField(
          schema_, field,
          CountNumberOfMutableFieldsVisitor{*this, field_count, val});
    }
    return field_count;
  }

  // Mutates the selected field.
  // The selected field index is based on the flattened tree.
  uint64_t MutateSelectedField(
      corpus_type& val, absl::BitGenRef prng,
      const domain_implementor::MutationMetadata& metadata, bool only_shrink,
      uint64_t selected_field_index) {
    uint64_t field_counter = 0;
    for (const auto* field : *object_->fields()) {
      if (IsSupportedField(field)) {
        if (only_shrink && !val.contains(field->id())) continue;
        ++field_counter;
      }

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
              derived()
                  .template GetCachedDomain<FlatbuffersStructTag>(field)
                  .MutateSelectedField(val[field->id()], prng, metadata,
                                       only_shrink,
                                       selected_field_index - field_counter);
        } else {
          field_counter +=
              derived()
                  .template GetCachedDomain<FlatbuffersTableTag>(field)
                  .MutateSelectedField(val[field->id()], prng, metadata,
                                       only_shrink,
                                       selected_field_index - field_counter);
        }
      }

      if (base_type == reflection::BaseType::Vector ||
          base_type == reflection::BaseType::Vector64) {
        auto elem_type = field->type()->element();
        if (elem_type == reflection::BaseType::Obj) {
          auto sub_object = schema_->objects()->Get(field->type()->index());
          if (!sub_object->is_struct()) {
            field_counter +=
                derived()
                    .template GetCachedDomain<
                        FlatbuffersVectorTag<FlatbuffersTableTag>>(field)
                    .MutateSelectedField(val[field->id()], prng, metadata,
                                         only_shrink,
                                         selected_field_index - field_counter);
          } else {
            field_counter +=
                derived()
                    .template GetCachedDomain<
                        FlatbuffersVectorTag<FlatbuffersStructTag>>(field)
                    .MutateSelectedField(val[field->id()], prng, metadata,
                                         only_shrink,
                                         selected_field_index - field_counter);
          }
        } else if (elem_type == reflection::BaseType::Union) {
          field_counter +=
              derived()
                  .template GetCachedDomain<
                      FlatbuffersVectorTag<FlatbuffersUnionTag>>(field)
                  .MutateSelectedField(val[field->id()], prng, metadata,
                                       only_shrink,
                                       selected_field_index - field_counter);
        }
      }

      if (base_type == reflection::BaseType::Union) {
        field_counter +=
            derived()
                .template GetCachedDomain<FlatbuffersUnionTag>(field)
                .MutateSelectedField(val[field->id()], prng, metadata,
                                     only_shrink,
                                     selected_field_index - field_counter);
      }

      if (field_counter > selected_field_index) {
        return field_counter;
      }
    }
    return field_counter;
  }

  auto GetPrinter() const { return Printer{*this}; }

  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const {
    for (const auto& [id, field_corpus] : corpus_value) {
      const reflection::Field* absl_nullable field = GetFieldById(id);
      if (field == nullptr) {
        return absl::InvalidArgumentError(
            absl::StrCat("Field id ", id, " is not found in the object."));
      }
      absl::Status result;
      VisitFlatbufferField(schema_, field,
                           ValidateVisitor{*this, field_corpus, result});
      if (!result.ok()) return result;
    }
    return absl::OkStatus();
  }

  value_type GetValue(const corpus_type& value) const {
    FUZZTEST_INTERNAL_CHECK(
        false, "GetValue is not supported for the untyped Flatbuffers domain.");
    // Untyped domain does not support GetValue since if it is a nested object
    // it would need the top level object corpus value to be able to build it.
    return nullptr;
  }

  // Converts the IRObject to a corpus value.
  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    corpus_type out;
    auto subs = obj.Subs();
    if (!subs) {
      return std::nullopt;
    }
    // Follows the structure created by `SerializeCorpus` to deserialize the
    // IRObject.

    // subs->size() represents the number of fields in the table.
    out.reserve(subs->size());
    for (const auto& sub : *subs) {
      auto pair_subs = sub.Subs();
      // Each field is represented by a pair of field id and the serialized
      // corpus value.
      if (!pair_subs || pair_subs->size() != 2) {
        return std::nullopt;
      }

      // Deserialize the field id.
      auto id = (*pair_subs)[0].GetScalar<typename corpus_type::key_type>();
      if (!id.has_value()) {
        return std::nullopt;
      }

      // Get information about the field from reflection.
      const reflection::Field* absl_nullable field = GetFieldById(id.value());
      if (field == nullptr) {
        return std::nullopt;
      }

      if (field->type()->base_type() == reflection::BaseType::UType) {
        // Union types are handled as part of the union field.
        continue;
      }

      // Deserialize the field corpus value.
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
  IRObject SerializeCorpus(const corpus_type& value) const {
    IRObject out;
    auto& subs = out.MutableSubs();
    subs.reserve(value.size());

    // Each field is represented by a pair of field id and the serialized
    // corpus value.
    for (const auto& [id, field_corpus] : value) {
      // Get information about the field from reflection.
      const reflection::Field* absl_nullable field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      IRObject& pair = subs.emplace_back();
      auto& pair_subs = pair.MutableSubs();
      pair_subs.reserve(2);

      // Serialize the field id.
      pair_subs.emplace_back(field->id());

      // Serialize the field corpus value.
      VisitFlatbufferField(
          schema_, field,
          SerializeVisitor{*this, field_corpus, pair_subs.emplace_back()});
    }
    return out;
  }

 protected:
  const reflection::Schema* schema_;
  const reflection::Object* object_;
  mutable absl::Mutex mutex_;
  mutable absl::flat_hash_map<
      decltype(static_cast<reflection::Field*>(nullptr)->id()), CopyableAny>
      domains_ ABSL_GUARDED_BY(mutex_);

  // Helper function to downcast to the derived type
  Derived& derived() { return static_cast<Derived&>(*this); }
  const Derived& derived() const { return static_cast<const Derived&>(*this); }

  bool IsSupportedField(const reflection::Field* absl_nonnull field) const {
    auto base_type = field->type()->base_type();
    if (flatbuffers::IsScalar(base_type)) return true;
    if (base_type == reflection::BaseType::String) return true;
    if (base_type == reflection::BaseType::Obj) return true;
    if (base_type == reflection::BaseType::Union) return true;
    if (base_type == reflection::BaseType::Vector ||
        base_type == reflection::BaseType::Vector64) {
      auto elem_type = field->type()->element();
      if (flatbuffers::IsScalar(elem_type)) return true;
      if (elem_type == reflection::BaseType::String) return true;
      if (elem_type == reflection::BaseType::Obj) return true;
      if (elem_type == reflection::BaseType::Union) return true;
    }
    if (base_type == reflection::BaseType::Array) {
      auto elem_type = field->type()->element();
      if (flatbuffers::IsScalar(elem_type)) return true;
      if (elem_type == reflection::BaseType::Obj &&
          schema_->objects()->Get(field->type()->index())->is_struct())
        return true;
    }
    return false;
  }

  const reflection::Field* absl_nullable GetFieldById(
      typename corpus_type::key_type id) const {
    const auto it =
        absl::c_find_if(*object_->fields(),
                        [id](const auto* field) { return field->id() == id; });
    return it != object_->fields()->end() ? *it : nullptr;
  }

  // Returns the domain for the given field.
  // The domain is cached, and the same instance is returned for the same
  // field.
  template <typename T>
  auto& GetCachedDomain(const reflection::Field* absl_nonnull field) const {
    using TypedDomainT = decltype(GetDefaultDomain<T>(schema_, field));
    using DomainT = Domain<value_type_t<TypedDomainT>>;
    // Do the operation under a lock to prevent race conditions in `const`
    // methods.
    absl::MutexLock l(&mutex_);
    auto it = domains_.find(field->id());
    if (it == domains_.end()) {
      it = domains_
               .try_emplace(field->id(), std::in_place_type<DomainT>,
                            DomainT{GetDefaultDomain<T>(schema_, field)})
               .first;
    }
    return it->second.template GetAs<DomainT>();
  }

  struct PrinterVisitor {
    const FlatbuffersUntypedObjectDomainBase<Derived, ValueType>& self;
    const GenericDomainCorpusType& field_corpus;
    domain_implementor::RawSink sink;
    domain_implementor::PrintMode mode;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) const {
      auto& domain = self.derived().template GetCachedDomain<T>(field);
      absl::Format(sink, "%s: ", field->name()->str());
      if constexpr (std::is_same_v<T, FlatbuffersVectorTag<uint8_t>> ||
                    std::is_same_v<
                        T, FlatbuffersVectorTag<FlatbuffersEnumTag<uint8_t>>> ||
                    std::is_same_v<T, FlatbuffersArrayTag<uint8_t>> ||
                    std::is_same_v<
                        T, FlatbuffersArrayTag<FlatbuffersEnumTag<uint8_t>>>) {
        // Handle the case where the field is a vector or array of uint8_t or
        // enum<uint8_t> since the container domain would try to print it as a
        // string.
        GenericDomainCorpusType object_corpus;
        if (field_corpus
                .Has<std::variant<std::monostate, GenericDomainCorpusType>>()) {
          auto opt_corpus = field_corpus.GetAs<
              std::variant<std::monostate, GenericDomainCorpusType>>();
          if (std::holds_alternative<GenericDomainCorpusType>(opt_corpus)) {
            object_corpus = std::get<GenericDomainCorpusType>(opt_corpus);
            absl::Format(sink, "(");
          } else {
            absl::Format(sink, "std::nullopt");
            return;
          }
        } else {
          object_corpus = field_corpus;
        }

        if constexpr (std::is_same_v<T, FlatbuffersVectorTag<uint8_t>> ||
                      std::is_same_v<T, FlatbuffersArrayTag<uint8_t>>) {
          auto inner_corpus = object_corpus.GetAs<corpus_type_t<
              ContainerOfImpl<std::vector<uint8_t>, ArbitraryImpl<uint8_t>>>>();
          auto inner_domain = Arbitrary<uint8_t>();
          auto printer = ContainerPrinter<
              ContainerOfImpl<std::vector<uint8_t>, ArbitraryImpl<uint8_t>>,
              ArbitraryImpl<uint8_t>>{inner_domain};
          printer.PrintCorpusValue(inner_corpus, sink, mode);
        } else if constexpr (
            std::is_same_v<T,
                           FlatbuffersVectorTag<FlatbuffersEnumTag<uint8_t>>> ||
            std::is_same_v<T,
                           FlatbuffersArrayTag<FlatbuffersEnumTag<uint8_t>>>) {
          auto inner_corpus = object_corpus.GetAs<corpus_type_t<ContainerOfImpl<
              std::vector<uint8_t>, FlatbuffersEnumDomainImpl<uint8_t>>>>();
          auto enum_object = self.schema_->enums()->Get(field->type()->index());
          auto inner_domain = FlatbuffersEnumDomainImpl<uint8_t>(enum_object);
          auto printer = ContainerPrinter<
              ContainerOfImpl<std::vector<uint8_t>,
                              FlatbuffersEnumDomainImpl<uint8_t>>,
              FlatbuffersEnumDomainImpl<uint8_t>>{inner_domain};
          printer.PrintCorpusValue(inner_corpus, sink, mode);
        }

        if (field_corpus
                .Has<std::variant<std::monostate, GenericDomainCorpusType>>()) {
          absl::Format(sink, ")");
        }
      } else {
        domain.GetPrinter().PrintCorpusValue(field_corpus, sink, mode);
      }
    }
  };

  struct Printer {
    const FlatbuffersUntypedObjectDomainBase<Derived, ValueType>& self;

    void PrintCorpusValue(const corpus_type& value,
                          domain_implementor::RawSink out,
                          domain_implementor::PrintMode mode) const {
      std::vector<typename corpus_type::key_type> field_ids;
      for (const auto& [id, _] : value) {
        field_ids.push_back(id);
      }
      // Sort the field ids to make the output deterministic.
      std::sort(field_ids.begin(), field_ids.end());

      absl::Format(out, "{");
      bool first = true;
      for (const auto id : field_ids) {
        if (!first) {
          absl::Format(out, ", ");
        }
        const reflection::Field* absl_nullable field = self.GetFieldById(id);
        if (field == nullptr) {
          absl::Format(out, "<unknown field: %d>", id);
        } else {
          VisitFlatbufferField(self.schema_, field,
                               PrinterVisitor{self, value.at(id), out, mode});
        }
        first = false;
      }
      absl::Format(out, "}");
    }
  };

  struct InitializeVisitor {
    const FlatbuffersUntypedObjectDomainBase<Derived, ValueType>& self;
    absl::BitGenRef prng;
    corpus_type& corpus;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = self.derived().template GetCachedDomain<T>(field);
      corpus[field->id()] = domain.Init(prng);
    }
  };

  struct CountNumberOfMutableFieldsVisitor {
    const FlatbuffersUntypedObjectDomainBase<Derived, ValueType>& self;
    uint64_t& field_count;
    corpus_type& corpus;
    bool only_shrink = false;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) const {
      if (!self.derived().IsSupportedField(field)) return;
      if (only_shrink && !corpus.contains(field->id())) return;

      field_count++;

      if constexpr (!std::is_integral_v<T> && !std::is_floating_point_v<T> &&
                    !is_flatbuffers_enum_tag_v<T>) {
        // Count the number of fields in sub-domain.
        auto& domain = self.derived().template GetCachedDomain<T>(field);
        if (auto it = corpus.find(field->id()); it != corpus.end()) {
          field_count += domain.CountNumberOfFields(it->second);
        }
      }
    }
  };

  struct MutateVisitor {
    const FlatbuffersUntypedObjectDomainBase<Derived, ValueType>& self;
    absl::BitGenRef prng;
    const domain_implementor::MutationMetadata& metadata;
    bool only_shrink;
    corpus_type& corpus;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = self.derived().template GetCachedDomain<T>(field);
      if (auto it = corpus.find(field->id()); it != corpus.end()) {
        domain.Mutate(it->second, prng, metadata, only_shrink);
      } else if (!only_shrink) {
        corpus[field->id()] = domain.Init(prng);
      }
    }
  };

  struct ParseVisitor {
    const FlatbuffersUntypedObjectDomainBase<Derived, ValueType>& self;
    const IRObject& ir_object;
    std::optional<GenericDomainCorpusType>& corpus;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = self.derived().template GetCachedDomain<T>(field);
      corpus = domain.ParseCorpus(ir_object);
    }
  };

  struct SerializeVisitor {
    const FlatbuffersUntypedObjectDomainBase<Derived, ValueType>& self;
    const GenericDomainCorpusType& corpus;
    IRObject& ir_object;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = self.derived().template GetCachedDomain<T>(field);
      ir_object = domain.SerializeCorpus(corpus);
    }
  };

  struct ValidateVisitor {
    const FlatbuffersUntypedObjectDomainBase<Derived, ValueType>& self;
    const GenericDomainCorpusType& inner_corpus;
    absl::Status& status;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = self.derived().template GetCachedDomain<T>(field);
      status = domain.ValidateCorpusValue(inner_corpus);
      if (!status.ok()) {
        status = Prefix(status, absl::StrCat("Invalid value for field ",
                                             field->name()->str()));
      }
    }
  };
};

// Domain implementation for flatbuffers struct types.
// The corpus type is a map of field ids to field values.
class FlatbuffersStructUntypedDomainImpl
    : public FlatbuffersUntypedObjectDomainBase<
          /*Derived=*/FlatbuffersStructUntypedDomainImpl,
          /*ValueType=*/const flatbuffers::Struct*> {
 public:
  template <typename Derived, typename ValueType>
  friend class FlatbuffersUntypedObjectDomainBase;

  using typename FlatbuffersStructUntypedDomainImpl::DomainBase::corpus_type;
  using typename FlatbuffersStructUntypedDomainImpl::DomainBase::value_type;

  explicit FlatbuffersStructUntypedDomainImpl(
      const reflection::Schema* absl_nonnull schema,
      const reflection::Object* absl_nonnull struct_object)
      : FlatbuffersUntypedObjectDomainBase(schema, struct_object) {
    FUZZTEST_INTERNAL_CHECK(struct_object->is_struct(),
                            "Object must be a struct type.");
  }

  // Converts the struct pointer to a corpus value.
  std::optional<corpus_type> FromValue(const value_type& value) const;

  // Builds the struct in a builder.
  std::optional<flatbuffers::uoffset_t> BuildValue(
      const corpus_type& value, flatbuffers::FlatBufferBuilder& builder) const;

  // Builds the struct in a buffer.
  void BuildValue(const corpus_type& value, uint8_t* buf) const;

 private:
  struct FromValueVisitor {
    const FlatbuffersStructUntypedDomainImpl& self;
    value_type value;
    corpus_type& out;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) const {
      [[maybe_unused]]
      reflection::BaseType base_type = field->type()->base_type();
      auto& domain = self.GetCachedDomain<T>(field);
      std::optional<corpus_type_t<std::decay_t<decltype(domain)>>> inner_corpus;

      if constexpr (is_flatbuffers_enum_tag_v<T>) {
        FUZZTEST_INTERNAL_CHECK(base_type >= reflection::BaseType::Byte &&
                                    base_type <= reflection::BaseType::ULong &&
                                    field->type()->index() >= 0,
                                "Field must be an enum type.");
        auto inner_value = value->GetField<typename T::type>(field->offset());
        inner_corpus = domain.FromValue(inner_value);
      } else if constexpr (std::is_integral_v<T> ||
                           std::is_floating_point_v<T>) {
        FUZZTEST_INTERNAL_CHECK(flatbuffers::IsScalar(base_type),
                                "Field must be an scalar type.");
        auto inner_value = value->GetField<T>(field->offset());
        inner_corpus = domain.FromValue(inner_value);
      } else if constexpr (std::is_same_v<T, FlatbuffersStructTag>) {
        auto sub_object = self.schema_->objects()->Get(field->type()->index());
        FUZZTEST_INTERNAL_CHECK(
            base_type == reflection::BaseType::Obj && sub_object->is_struct(),
            "Field must be a struct type.");
        auto inner_value =
            value->GetStruct<const flatbuffers::Struct*>(field->offset());
        inner_corpus = domain.FromValue(inner_value);
      } else if constexpr (is_flatbuffers_array_tag_v<T>) {
        using ValueT = typename T::value_type;
        auto element_type = field->type()->element();
        if constexpr (std::is_integral_v<ValueT> ||
                      std::is_floating_point_v<ValueT>) {
          FUZZTEST_INTERNAL_CHECK(flatbuffers::IsScalar(element_type),
                                  "Field element type must be an scalar type.");
          std::vector<ValueT> inner_values;
          for (size_t i = 0; i < field->type()->fixed_length(); ++i) {
            auto inner_value = value->GetField<ValueT>(
                field->offset() + i * field->type()->element_size());
            inner_values.push_back(inner_value);
          }
          inner_corpus = domain.FromValue(inner_values);
        } else if constexpr (is_flatbuffers_enum_tag_v<ValueT>) {
          FUZZTEST_INTERNAL_CHECK(flatbuffers::IsScalar(element_type) &&
                                      element_type != reflection::Bool,
                                  "Field element type must be an scalar type.");
          std::vector<typename ValueT::type> inner_values;
          for (size_t i = 0; i < field->type()->fixed_length(); ++i) {
            auto inner_value = value->GetField<typename ValueT::type>(
                field->offset() + i * field->type()->element_size());
            inner_values.push_back(inner_value);
          }
          inner_corpus = domain.FromValue(inner_values);
        } else if constexpr (std::is_same_v<ValueT, FlatbuffersStructTag>) {
          auto sub_object =
              self.schema_->objects()->Get(field->type()->index());
          FUZZTEST_INTERNAL_CHECK(element_type == reflection::BaseType::Obj &&
                                      sub_object->is_struct(),
                                  "Field element type must be a struct type.");
          std::vector<const flatbuffers::Struct*> inner_values;
          for (size_t i = 0; i < field->type()->fixed_length(); ++i) {
            auto inner_value = value->GetStruct<const flatbuffers::Struct*>(
                field->offset() + i * sub_object->bytesize());
            inner_values.push_back(inner_value);
          }
          inner_corpus = domain.FromValue(inner_values);
        }
      }

      if (inner_corpus.has_value()) {
        out[field->id()] = std::move(*inner_corpus);
      }
    };
  };

  struct BuildValueVisitor {
    const FlatbuffersStructUntypedDomainImpl& self;
    const corpus_type& corpus_value;
    uint8_t* struct_ptr;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) const {
      [[maybe_unused]]
      reflection::BaseType base_type = field->type()->base_type();
      auto& domain = self.GetCachedDomain<T>(field);
      if constexpr (is_flatbuffers_enum_tag_v<T> || std::is_integral_v<T> ||
                    std::is_floating_point_v<T>) {
        FUZZTEST_INTERNAL_CHECK(flatbuffers::IsScalar(base_type),
                                "Field must be an scalar type.");
        auto inner_value = domain.GetValue(corpus_value.at(field->id()));
        if constexpr (is_flatbuffers_enum_tag_v<T>) {
          flatbuffers::WriteScalar<typename T::type>(
              struct_ptr + field->offset(), inner_value);
        } else {
          flatbuffers::WriteScalar<T>(struct_ptr + field->offset(),
                                      inner_value);
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersStructTag>) {
        auto sub_object = self.schema_->objects()->Get(field->type()->index());
        FUZZTEST_INTERNAL_CHECK(
            base_type == reflection::BaseType::Obj && sub_object->is_struct(),
            "Field must be a struct type.");
        auto inner_corpus_value =
            corpus_value.at(field->id())
                .GetAs<FlatbuffersStructUntypedDomainImpl::corpus_type>();
        FlatbuffersStructUntypedDomainImpl sub_domain(self.schema_, sub_object);
        for (const auto* nested_field : *sub_object->fields()) {
          VisitFlatbufferField(sub_domain.schema_, nested_field,
                               BuildValueVisitor{sub_domain, inner_corpus_value,
                                                 struct_ptr + field->offset()});
        }
      } else if constexpr (is_flatbuffers_array_tag_v<T>) {
        if constexpr (is_flatbuffers_enum_tag_v<typename T::value_type> ||
                      std::is_integral_v<typename T::value_type> ||
                      std::is_floating_point_v<typename T::value_type>) {
          FUZZTEST_INTERNAL_CHECK(
              flatbuffers::IsScalar(field->type()->element()),
              "Field must be an scalar type.");
          auto inner_values = domain.GetValue(corpus_value.at(field->id()));
          for (size_t i = 0; i < field->type()->fixed_length(); ++i) {
            auto offset = field->offset() + i * field->type()->element_size();
            if constexpr (is_flatbuffers_enum_tag_v<typename T::value_type>) {
              flatbuffers::WriteScalar<typename T::value_type::type>(
                  struct_ptr + offset, inner_values[i]);
            } else {
              flatbuffers::WriteScalar<typename T::value_type>(
                  struct_ptr + offset, inner_values[i]);
            }
          }
        } else if constexpr (std::is_same_v<typename T::value_type,
                                            FlatbuffersStructTag>) {
          auto sub_object =
              self.schema_->objects()->Get(field->type()->index());
          FUZZTEST_INTERNAL_CHECK(
              field->type()->element() == reflection::BaseType::Obj &&
                  sub_object->is_struct(),
              "Field must be a struct type.");
          auto container_corpus =
              corpus_value.at(field->id()).GetAs<std::list<corpus_type>>();
          FlatbuffersStructUntypedDomainImpl sub_domain(self.schema_,
                                                        sub_object);
          size_t i = 0;
          for (const auto& element_corpus : container_corpus) {
            for (const auto* nested_field : *sub_object->fields()) {
              VisitFlatbufferField(
                  sub_domain.schema_, nested_field,
                  BuildValueVisitor{sub_domain, element_corpus,
                                    struct_ptr + field->offset() +
                                        i * sub_object->bytesize()});
            }
            ++i;
          }
        }
      }
    }
  };
};

// Union domain corpus type.
struct FlatbuffersUnionDomainCorpusType {
  using type_type = typename FlatbuffersUnionTypeDomainImpl::corpus_type;
  using value_type = GenericDomainCorpusType;

  type_type type;
  value_type value;
};

// Union domain value type.
struct FlatbuffersUnionDomainValueType {
  using type_type = typename FlatbuffersUnionTypeDomainImpl::value_type;
  using value_type = const void*;

  type_type type;
  value_type value;
};

// Flatbuffers union domain implementation.
class FlatbuffersUnionDomainImpl
    : public domain_implementor::DomainBase<
          /*Derived=*/FlatbuffersUnionDomainImpl,
          /*ValueType=*/FlatbuffersUnionDomainValueType,
          /*CorpusType=*/FlatbuffersUnionDomainCorpusType> {
 public:
  friend class FlatbuffersTableUntypedDomainImpl;

  using typename FlatbuffersUnionDomainImpl::DomainBase::corpus_type;
  using typename FlatbuffersUnionDomainImpl::DomainBase::value_type;

  FlatbuffersUnionDomainImpl(const reflection::Schema* schema,
                             const reflection::Enum* union_def)
      : schema_(schema), union_def_(union_def), type_domain_(union_def) {}

  FlatbuffersUnionDomainImpl(const FlatbuffersUnionDomainImpl& other)
      : schema_(other.schema_),
        union_def_(other.union_def_),
        type_domain_(other.type_domain_) {
    absl::MutexLock l(&mutex_);
    absl::MutexLock l_other(&other.mutex_);
    domains_ = other.domains_;
  }

  FlatbuffersUnionDomainImpl(FlatbuffersUnionDomainImpl&& other)
      : schema_(other.schema_),
        union_def_(other.union_def_),
        type_domain_(std::move(other.type_domain_)) {
    absl::MutexLock l(&mutex_);
    absl::MutexLock l_other(&other.mutex_);
    domains_ = std::move(other.domains_);
  }

  FlatbuffersUnionDomainImpl& operator=(
      const FlatbuffersUnionDomainImpl& other) {
    schema_ = other.schema_;
    union_def_ = other.union_def_;
    type_domain_ = other.type_domain_;
    absl::MutexLock l(&mutex_);
    absl::MutexLock l_other(&other.mutex_);
    domains_ = other.domains_;
    return *this;
  }

  FlatbuffersUnionDomainImpl& operator=(FlatbuffersUnionDomainImpl&& other) {
    schema_ = other.schema_;
    union_def_ = other.union_def_;
    type_domain_ = std::move(other.type_domain_);
    absl::MutexLock l(&mutex_);
    absl::MutexLock l_other(&other.mutex_);
    domains_ = std::move(other.domains_);
    return *this;
  }

  // Initializes the corpus value.
  corpus_type Init(absl::BitGenRef prng);

  // Mutates the corpus value.
  void Mutate(corpus_type& corpus_value, absl::BitGenRef prng,
              const domain_implementor::MutationMetadata& metadata,
              bool only_shrink);

  uint64_t CountNumberOfFields(corpus_type& corpus_value);

  auto GetPrinter() const { return Printer{*this}; }

  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const;

  // UNSUPPORTED: Flatbuffers unions user values are not supported.
  value_type GetValue(const corpus_type& corpus_value) const {
    FUZZTEST_INTERNAL_CHECK(false, "GetValue is not supported for unions.");
  }

  // Gets the type of the union field.
  auto GetType(const corpus_type& corpus_value) const {
    return type_domain_.GetValue(corpus_value.type);
  }

  // Converts the value to a corpus value.
  std::optional<corpus_type> FromValue(const value_type& value) const;

  // Converts the IRObject to a corpus value.
  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const;

  // Converts the corpus value to an IRObject.
  IRObject SerializeCorpus(const corpus_type& corpus_value) const;

 private:
  const reflection::Schema* schema_;
  const reflection::Enum* union_def_;
  FlatbuffersEnumDomainImpl<typename FlatbuffersUnionTypeDomainImpl::value_type>
      type_domain_;
  mutable absl::Mutex mutex_;
  mutable absl::flat_hash_map<
      typename FlatbuffersUnionTypeDomainImpl::value_type, CopyableAny>
      domains_ ABSL_GUARDED_BY(mutex_);

  // Creates flatbuffer from the corpus value.
  std::optional<flatbuffers::uoffset_t> BuildValue(
      const corpus_type& corpus_value,
      flatbuffers::FlatBufferBuilder& builder) const;

  // Returns the domain for the given enum value.
  template <typename T>
  auto& GetCachedDomain(const reflection::EnumVal& enum_value) const {
    using DomainT = decltype(GetDefaultDomainForType<T>(enum_value));
    absl::MutexLock l(&mutex_);
    auto it = domains_.find(enum_value.value());
    if (it == domains_.end()) {
      it = domains_
               .try_emplace(enum_value.value(), std::in_place_type<DomainT>,
                            GetDefaultDomainForType<T>(enum_value))
               .first;
    }
    return it->second.GetAs<DomainT>();
  }

  // Creates new or returns existing domain for the given enum value.
  template <typename T>
  auto GetDefaultDomainForType(const reflection::EnumVal& enum_value) const;

  struct Printer {
    const FlatbuffersUnionDomainImpl& self;

    void PrintCorpusValue(const corpus_type& value,
                          domain_implementor::RawSink out,
                          domain_implementor::PrintMode mode) const;
  };
};

// Domain implementation for flatbuffers untyped tables.
// The corpus type is a map of field ids to field values.
class FlatbuffersTableUntypedDomainImpl
    : public FlatbuffersUntypedObjectDomainBase<
          /*Derived=*/FlatbuffersTableUntypedDomainImpl,
          /*ValueType=*/const flatbuffers::Table*> {
 public:
  template <typename Derived, typename ValueType>
  friend class FlatbuffersUntypedObjectDomainBase;
  template <typename T>
  friend class FlatbuffersTableDomainImpl;
  friend class FlatbuffersUnionDomainImpl;

  using typename FlatbuffersTableUntypedDomainImpl::DomainBase::corpus_type;
  using typename FlatbuffersTableUntypedDomainImpl::DomainBase::value_type;

  explicit FlatbuffersTableUntypedDomainImpl(
      const reflection::Schema* absl_nonnull schema,
      const reflection::Object* absl_nonnull table_object)
      : FlatbuffersUntypedObjectDomainBase(schema, table_object) {}

  // Converts the table pointer to a corpus value.
  std::optional<corpus_type> FromValue(const value_type& value) const;

 private:
  uint32_t BuildTable(const corpus_type& value,
                      flatbuffers::FlatBufferBuilder& builder) const;

  // Returns the domain for the given field.
  // The domain is cached, and the same instance is returned for the same
  // field.
  template <typename T>
  auto& GetCachedDomain(const reflection::Field* absl_nonnull field) const {
    auto get_opt_domain = [this, field]() {
      auto opt_domain = OptionalOf(GetDefaultDomain<T>(schema_, field));
      if (!field->optional()) opt_domain.SetWithoutNull();
      return Domain<value_type_t<decltype(opt_domain)>>{opt_domain};
    };

    using DomainT = decltype(get_opt_domain());
    // Do the operation under a lock to prevent race conditions in `const`
    // methods.
    absl::MutexLock l(&mutex_);
    auto it = domains_.find(field->id());
    if (it == domains_.end()) {
      it = domains_
               .try_emplace(field->id(), std::in_place_type<DomainT>,
                            get_opt_domain())
               .first;
    }
    return it->second.template GetAs<DomainT>();
  }

  struct FromValueVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    value_type user_value;
    corpus_type& corpus_value;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) const {
      [[maybe_unused]]
      reflection::BaseType base_type = field->type()->base_type();
      auto& domain = self.GetCachedDomain<T>(field);
      value_type_t<std::decay_t<decltype(domain)>> inner_value;

      if constexpr (is_flatbuffers_enum_tag_v<T>) {
        if (!field->optional() || user_value->CheckField(field->offset())) {
          inner_value = user_value->GetField<typename T::type>(
              field->offset(), field->default_integer());
        }
      } else if constexpr (std::is_integral_v<T>) {
        if (!field->optional() || user_value->CheckField(field->offset())) {
          inner_value = std::optional(user_value->GetField<T>(
              field->offset(), field->default_integer()));
        }
      } else if constexpr (std::is_floating_point_v<T>) {
        if (!field->optional() || user_value->CheckField(field->offset())) {
          inner_value = std::optional(
              user_value->GetField<T>(field->offset(), field->default_real()));
        }
      } else if constexpr (std::is_same_v<T, std::string>) {
        if (user_value->CheckField(field->offset())) {
          inner_value = std::optional(
              user_value->GetPointer<flatbuffers::String*>(field->offset())
                  ->str());
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersTableTag>) {
        auto sub_object = self.schema_->objects()->Get(field->type()->index());
        FUZZTEST_INTERNAL_CHECK(
            base_type == reflection::BaseType::Obj && !sub_object->is_struct(),
            "Field must be a table type.");
        inner_value =
            user_value->GetPointer<const flatbuffers::Table*>(field->offset());
      } else if constexpr (std::is_same_v<T, FlatbuffersStructTag>) {
        auto sub_object = self.schema_->objects()->Get(field->type()->index());
        FUZZTEST_INTERNAL_CHECK(
            base_type == reflection::BaseType::Obj && sub_object->is_struct(),
            "Field must be a struct type.");
        inner_value =
            user_value->GetStruct<const flatbuffers::Struct*>(field->offset());
      } else if constexpr (is_flatbuffers_vector_tag_v<T>) {
        FUZZTEST_INTERNAL_CHECK(base_type == reflection::BaseType::Vector ||
                                    base_type == reflection::BaseType::Vector64,
                                "Field must be a vector type.");
        if (!user_value->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          VisitVector<typename T::value_type, std::decay_t<decltype(domain)>>(
              field, inner_value);
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersUnionTag>) {
        constexpr char kUnionTypeFieldSuffix[] = "_type";
        auto enumdef = self.schema_->enums()->Get(field->type()->index());
        auto type_field = self.object_->fields()->LookupByKey(
            (field->name()->str() + kUnionTypeFieldSuffix).c_str());
        if (type_field == nullptr) {
          return;
        }
        auto union_type =
            user_value->GetField<uint8_t>(type_field->offset(), 0);
        if (union_type > 0 /* NONE */) {
          auto enumval = enumdef->values()->LookupByKey(union_type);
          auto union_object =
              self.schema_->objects()->Get(enumval->union_type()->index());
          if (union_object->is_struct()) {
            auto union_value =
                user_value->template GetPointer<flatbuffers::Struct*>(
                    field->offset());
            inner_value =
                FlatbuffersUnionDomainValueType{union_type, union_value};
          } else {
            auto union_value =
                user_value->GetPointer<flatbuffers::Table*>(field->offset());
            inner_value =
                FlatbuffersUnionDomainValueType{union_type, union_value};
          }
        }
      }

      auto inner = domain.FromValue(inner_value);
      if (inner) {
        corpus_value[field->id()] = std::move(inner.value());
      }
    };

    template <typename ElementType, typename Domain>
    void VisitVector(const reflection::Field* field,
                     value_type_t<Domain>& inner_value) const {
      if constexpr (std::is_integral_v<ElementType> ||
                    std::is_floating_point_v<ElementType>) {
        auto vec = user_value->GetPointer<flatbuffers::Vector<ElementType>*>(
            field->offset());
        inner_value = std::optional(std::vector<ElementType>());
        inner_value->reserve(vec->size());
        for (auto i = 0; i < vec->size(); ++i) {
          inner_value->push_back(vec->Get(i));
        }
      } else if constexpr (is_flatbuffers_enum_tag_v<ElementType>) {
        using Underlaying = typename ElementType::type;
        auto vec = user_value->GetPointer<flatbuffers::Vector<Underlaying>*>(
            field->offset());
        inner_value = std::optional(std::vector<Underlaying>());
        inner_value->reserve(vec->size());
        for (auto i = 0; i < vec->size(); ++i) {
          inner_value->push_back(vec->Get(i));
        }
      } else if constexpr (std::is_same_v<ElementType, std::string>) {
        auto vec = user_value->GetPointer<
            flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>>*>(
            field->offset());
        inner_value = std::optional(std::vector<std::string>());
        inner_value->reserve(vec->size());
        for (auto i = 0; i < vec->size(); ++i) {
          inner_value->push_back(vec->Get(i)->str());
        }
      } else if constexpr (std::is_same_v<ElementType, FlatbuffersTableTag>) {
        auto vec = user_value->GetPointer<
            flatbuffers::Vector<flatbuffers::Offset<flatbuffers::Table>>*>(
            field->offset());
        inner_value = std::optional(std::vector<const flatbuffers::Table*>());
        inner_value->reserve(vec->size());
        for (auto i = 0; i < vec->size(); ++i) {
          inner_value->push_back(vec->Get(i));
        }
      } else if constexpr (std::is_same_v<ElementType, FlatbuffersStructTag>) {
        const reflection::Object* struct_object =
            self.schema_->objects()->Get(field->type()->index());
        auto vec =
            user_value
                ->template GetPointer<const flatbuffers::Vector<uint8_t>*>(
                    field->offset());
        if (vec == nullptr) {
          return;
        }
        inner_value =
            std::make_optional(std::vector<const flatbuffers::Struct*>());
        inner_value->reserve(vec->size());
        for (std::remove_pointer_t<decltype(vec)>::size_type i = 0;
             i < vec->size(); ++i) {
          const uint8_t* struct_data_ptr =
              vec->Data() + i * struct_object->bytesize();
          inner_value->push_back(
              reinterpret_cast<const flatbuffers::Struct*>(struct_data_ptr));
        }
      } else if constexpr (std::is_same_v<ElementType, FlatbuffersUnionTag>) {
        constexpr char kUnionTypeFieldSuffix[] = "_type";
        auto type_field = self.object_->fields()->LookupByKey(
            (field->name()->str() + kUnionTypeFieldSuffix).c_str());
        if (type_field == nullptr) {
          return;
        }
        auto type_vec = user_value->GetPointer<flatbuffers::Vector<uint8_t>*>(
            type_field->offset());
        auto value_vec =
            user_value
                ->GetPointer<flatbuffers::Vector<flatbuffers::Offset<void>>*>(
                    field->offset());
        inner_value =
            std::optional(typename value_type_t<Domain>::value_type{});
        inner_value->reserve(value_vec->size());
        for (auto i = 0; i < value_vec->size(); ++i) {
          inner_value->emplace_back(type_vec->Get(i), value_vec->Get(i));
        }
      }
    }
  };

  // Create out-of-line table fields, see `BuildTable` for details.
  struct TableFieldBuilderVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    flatbuffers::FlatBufferBuilder& builder;
    absl::flat_hash_map<typename corpus_type::key_type, flatbuffers::uoffset_t>&
        offsets;
    const typename corpus_type::mapped_type& corpus_value;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      if constexpr (std::is_same_v<T, std::string>) {
        auto& domain = self.GetCachedDomain<T>(field);
        auto user_value = domain.GetValue(corpus_value);
        if (user_value.has_value()) {
          auto offset =
              builder.CreateString(user_value->data(), user_value->size()).o;
          offsets.insert({field->id(), offset});
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersTableTag>) {
        FlatbuffersTableUntypedDomainImpl inner_domain(
            self.schema_, self.schema_->objects()->Get(field->type()->index()));
        auto opt_corpus =
            corpus_value
                .GetAs<std::variant<std::monostate, GenericDomainCorpusType>>();
        if (std::holds_alternative<GenericDomainCorpusType>(opt_corpus)) {
          auto inner_corpus = std::get<GenericDomainCorpusType>(opt_corpus)
                                  .GetAs<corpus_type>();
          auto offset = inner_domain.BuildTable(inner_corpus, builder);
          offsets.insert({field->id(), offset});
        }
      } else if constexpr (is_flatbuffers_vector_tag_v<T>) {
        VisitVector<typename T::value_type>(field,
                                            self.GetCachedDomain<T>(field));
      } else if constexpr (std::is_same_v<T, FlatbuffersUnionTag>) {
        const reflection::Enum* union_type =
            self.schema_->enums()->Get(field->type()->index());
        FlatbuffersUnionDomainImpl inner_domain{self.schema_, union_type};
        auto opt_corpus =
            corpus_value
                .GetAs<std::variant<std::monostate, GenericDomainCorpusType>>();
        if (std::holds_alternative<GenericDomainCorpusType>(opt_corpus)) {
          auto inner_corpus =
              std::get<GenericDomainCorpusType>(opt_corpus)
                  .GetAs<corpus_type_t<decltype(inner_domain)>>();
          auto offset = inner_domain.BuildValue(inner_corpus, builder);
          if (offset.has_value()) {
            offsets.insert({field->id(), *offset});
          }
        }
      }
    }

   private:
    template <typename Element, typename Domain,
              std::enable_if_t<std::is_integral_v<Element> ||
                                   std::is_floating_point_v<Element> ||
                                   is_flatbuffers_enum_tag_v<Element>,
                               int> = 0>
    void VisitVector(const reflection::Field* field, const Domain& domain) {
      auto value = domain.GetValue(corpus_value);
      if (value && (!value->empty() || !field->optional())) {
        offsets.insert({field->id(), builder.CreateVector(*value).o});
      } else if (!value && !field->optional()) {
        // Handle case where value is std::nullopt but field is not optional
        // Create an empty vector of the appropriate type.
        if constexpr (is_flatbuffers_enum_tag_v<Element>) {
          offsets.insert(
              {field->id(),
               builder.CreateVector(std::vector<typename Element::type>()).o});
        } else {
          offsets.insert(
              {field->id(), builder.CreateVector(std::vector<Element>()).o});
        }
      }
    }

    template <
        typename Element, typename Domain,
        std::enable_if_t<std::is_same_v<Element, FlatbuffersTableTag>, int> = 0>
    void VisitVector(const reflection::Field* field, const Domain& domain) {
      auto opt_corpus =
          corpus_value
              .GetAs<std::variant<std::monostate, GenericDomainCorpusType>>();
      if (std::holds_alternative<std::monostate>(opt_corpus)) {
        return;
      }
      auto container_corpus = std::get<GenericDomainCorpusType>(opt_corpus)
                                  .GetAs<std::list<corpus_type>>();
      if (field->optional() && container_corpus.empty()) {
        return;
      }

      FlatbuffersTableUntypedDomainImpl inner_domain(
          self.schema_, self.schema_->objects()->Get(field->type()->index()));
      std::vector<flatbuffers::Offset<flatbuffers::Table>> vec_offsets;
      vec_offsets.reserve(container_corpus.size());
      for (auto& inner_corpus : container_corpus) {
        auto offset = inner_domain.BuildTable(inner_corpus, builder);
        vec_offsets.push_back(offset);
      }
      offsets.insert({field->id(), builder.CreateVector(vec_offsets).o});
    }

    template <typename Element, typename Domain,
              std::enable_if_t<std::is_same_v<Element, FlatbuffersStructTag>,
                               int> = 0>
    void VisitVector(const reflection::Field* field, const Domain& domain) {
      auto struct_object = self.schema_->objects()->Get(field->type()->index());
      auto opt_corpus = corpus_value.template GetAs<
          std::variant<std::monostate, GenericDomainCorpusType>>();
      if (std::holds_alternative<std::monostate>(opt_corpus)) {
        return;
      }
      auto container_corpus = std::get<GenericDomainCorpusType>(opt_corpus)
                                  .template GetAs<std::list<corpus_type>>();
      uint8_t* vec_ptr = nullptr;
      FlatbuffersStructUntypedDomainImpl inner_domain(self.schema_,
                                                      struct_object);
      auto vec_offset = builder.CreateUninitializedVector(
          container_corpus.size(), struct_object->bytesize(),
          struct_object->minalign(), &vec_ptr);
      size_t i = 0;
      for (const auto& inner_corpus : container_corpus) {
        uint8_t* current_struct_ptr = vec_ptr + i * struct_object->bytesize();
        inner_domain.BuildValue(inner_corpus, current_struct_ptr);
        ++i;
      }
      offsets.insert({field->id(), vec_offset});
    }

    template <typename Element, typename Domain,
              std::enable_if_t<std::is_same_v<Element, std::string>, int> = 0>
    void VisitVector(const reflection::Field* field, const Domain& domain) {
      auto value = domain.GetValue(corpus_value);
      if (!value) {
        return;
      }
      std::vector<flatbuffers::Offset<flatbuffers::String>> vec_offsets;
      vec_offsets.reserve(value->size());
      for (const auto& str : *value) {
        auto offset = builder.CreateString(str);
        vec_offsets.push_back(offset);
      }
      offsets.insert({field->id(), builder.CreateVector(vec_offsets).o});
    }

    template <
        typename Element, typename Domain,
        std::enable_if_t<std::is_same_v<Element, FlatbuffersUnionTag>, int> = 0>
    void VisitVector(const reflection::Field* field, const Domain& domain) {
      const reflection::Enum* union_type =
          self.schema_->enums()->Get(field->type()->index());
      constexpr char kUnionTypeFieldSuffix[] = "_type";
      const reflection::Field* type_field = self.object_->fields()->LookupByKey(
          (field->name()->str() + kUnionTypeFieldSuffix).c_str());

      auto opt_corpus =
          corpus_value
              .GetAs<std::variant<std::monostate, GenericDomainCorpusType>>();
      if (std::holds_alternative<std::monostate>(opt_corpus)) {
        return;
      }
      FlatbuffersUnionDomainImpl inner_domain{self.schema_, union_type};
      auto container_corpus =
          std::get<GenericDomainCorpusType>(opt_corpus)
              .GetAs<std::list<corpus_type_t<decltype(inner_domain)>>>();

      std::vector<typename value_type_t<
          std::decay_t<decltype(inner_domain)>>::type_type>
          vec_types;
      vec_types.reserve(container_corpus.size());
      std::vector<flatbuffers::Offset<flatbuffers::Table>> vec_offsets;
      vec_offsets.reserve(container_corpus.size());
      for (auto& inner_corpus : container_corpus) {
        auto offset = inner_domain.BuildValue(inner_corpus, builder);
        if (offset.has_value()) {
          vec_offsets.push_back(*offset);
          vec_types.push_back(inner_domain.GetType(inner_corpus));
        }
      }
      offsets.insert({field->id(), builder.CreateVector(vec_offsets).o});
      offsets.insert({type_field->id(), builder.CreateVector(vec_types).o});
    }
  };

  // Create complete table: store "inline fields" values inline, and store
  // just offsets for "out-of-line fields". See `BuildTable` for details.
  struct TableBuilderVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    flatbuffers::FlatBufferBuilder& builder;
    absl::flat_hash_map<typename corpus_type::key_type, flatbuffers::uoffset_t>&
        offsets;
    const typename corpus_type::value_type::second_type& corpus_value;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) const {
      if constexpr (std::is_integral_v<T> || std::is_floating_point_v<T> ||
                    is_flatbuffers_enum_tag_v<T>) {
        auto& domain = self.GetCachedDomain<T>(field);
        auto v = domain.GetValue(corpus_value);
        if (!v) {
          return;
        }
        // Store "inline field" value inline.
        builder.AddElement(field->offset(), v.value());
      } else if constexpr (std::is_same_v<T, std::string> ||
                           is_flatbuffers_vector_tag_v<T>) {
        // "Out-of-line field". Store just offset.
        if constexpr (is_flatbuffers_vector_tag_v<T>) {
          if constexpr (std::is_same_v<typename T::value_type,
                                       FlatbuffersUnionTag>) {
            constexpr char kUnionTypeFieldSuffix[] = "_type";
            const reflection::Field* type_field =
                self.object_->fields()->LookupByKey(
                    (field->name()->str() + kUnionTypeFieldSuffix).c_str());
            if (auto it = offsets.find(type_field->id()); it != offsets.end()) {
              builder.AddOffset(type_field->offset(),
                                flatbuffers::Offset<>(it->second));
            }
          }
        }
        if (auto it = offsets.find(field->id()); it != offsets.end()) {
          builder.AddOffset(
              field->offset(),
              flatbuffers::Offset<flatbuffers::String>(it->second));
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersTableTag>) {
        // "Out-of-line field". Store just offset.
        if (auto it = offsets.find(field->id()); it != offsets.end()) {
          builder.AddOffset(
              field->offset(),
              flatbuffers::Offset<flatbuffers::Table>(it->second));
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersStructTag>) {
        FlatbuffersStructUntypedDomainImpl domain(
            self.schema_, self.schema_->objects()->Get(field->type()->index()));
        auto opt_corpus = corpus_value.template GetAs<
            std::variant<std::monostate, GenericDomainCorpusType>>();
        if (std::holds_alternative<std::monostate>(opt_corpus)) {
          return;
        }
        auto inner_corpus =
            std::get<GenericDomainCorpusType>(opt_corpus)
                .template GetAs<corpus_type_t<decltype(domain)>>();
        auto offset = domain.BuildValue(inner_corpus, builder);
        if (offset.has_value()) {
          builder.AddStructOffset(field->offset(), offset.value());
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersUnionTag>) {
        // From flatbuffers documentation:
        // Unions are encoded as the combination of two fields: an enum
        // representing the union choice and the offset to the actual element
        const reflection::Enum* union_type =
            self.schema_->enums()->Get(field->type()->index());
        FlatbuffersUnionDomainImpl domain(self.schema_, union_type);
        if (auto it = offsets.find(field->id()); it != offsets.end()) {
          // Store just an offset to the actual union element.
          builder.AddOffset(field->offset(),
                            flatbuffers::Offset<void>(it->second));

          constexpr char kUnionTypeFieldSuffix[] = "_type";
          const reflection::Field* type_field =
              self.object_->fields()->LookupByKey(
                  (field->name()->str() + kUnionTypeFieldSuffix).c_str());
          auto opt_corpus = corpus_value.GetAs<
              std::variant<std::monostate, GenericDomainCorpusType>>();
          if (std::holds_alternative<std::monostate>(opt_corpus)) {
            return;
          }
          auto inner_corpus = std::get<GenericDomainCorpusType>(opt_corpus)
                                  .GetAs<corpus_type_t<decltype(domain)>>();
          auto type_value = domain.GetType(inner_corpus);
          auto size = flatbuffers::GetTypeSize(type_field->type()->base_type());
          // Store the type value inline.
          builder.Align(size);
          builder.PushBytes(reinterpret_cast<const uint8_t*>(&type_value),
                            size);
          builder.TrackField(type_field->offset(), builder.GetSize());
        }
      }
    }
  };
};

// Domain factory for flatbuffers fields.
template <typename T>
auto GetDefaultDomain(const reflection::Schema* absl_nonnull schema,
                      const reflection::Field* absl_nonnull field) {
  // Used to satisfy the compiler return type deduction rules.
  auto placeholder = Arbitrary<bool>();

  if constexpr (is_flatbuffers_array_tag_v<T>) {
    using ElementT = typename T::value_type;
    auto size = field->type()->fixed_length();
    if constexpr (is_flatbuffers_enum_tag_v<ElementT>) {
      auto enum_object = schema->enums()->Get(field->type()->index());
      return VectorOf(FlatbuffersEnumDomainImpl<typename ElementT::type>(
                          enum_object))
          .WithSize(size);
    } else if constexpr (std::is_same_v<ElementT, FlatbuffersStructTag>) {
      const reflection::Object* sub_object =
          schema->objects()->Get(field->type()->index());
      return VectorOf(FlatbuffersStructUntypedDomainImpl{schema, sub_object})
          .WithSize(size);
    } else if constexpr (std::is_integral_v<ElementT> ||
                         std::is_floating_point_v<ElementT>) {
      return VectorOf(Arbitrary<ElementT>()).WithSize(size);
    } else {
      FUZZTEST_INTERNAL_CHECK(false,
                              "Unsupported type: ", field->type()->element());
      return VectorOf(placeholder).WithSize(0);
    }
  } else if constexpr (is_flatbuffers_enum_tag_v<T>) {
    auto enum_object = schema->enums()->Get(field->type()->index());
    return FlatbuffersEnumDomainImpl<typename T::type>(enum_object);
  } else if constexpr (std::is_same_v<T, FlatbuffersTableTag>) {
    auto table_object = schema->objects()->Get(field->type()->index());
    return FlatbuffersTableUntypedDomainImpl{schema, table_object};
  } else if constexpr (std::is_same_v<T, FlatbuffersStructTag>) {
    auto struct_object = schema->objects()->Get(field->type()->index());
    return FlatbuffersStructUntypedDomainImpl{schema, struct_object};
  } else if constexpr (std::is_same_v<T, FlatbuffersUnionTag>) {
    auto union_type = schema->enums()->Get(field->type()->index());
    return FlatbuffersUnionDomainImpl{schema, union_type};
  } else if constexpr (is_flatbuffers_vector_tag_v<T>) {
    return VectorOf(GetDefaultDomain<typename T::value_type>(schema, field))
        .WithMaxSize(std::numeric_limits<flatbuffers::uoffset_t>::max());
  } else {
    return Arbitrary<T>();
  }
}

// Corpus type for the table domain
struct FlatbuffersTableDomainCorpusType {
  // Map of field ids to field values.
  typename FlatbuffersTableUntypedDomainImpl::corpus_type untyped_corpus;
  // Serialized flatbuffer.
  mutable std::vector<uint8_t> buffer;
};

// Domain implementation for flatbuffers generated table classes.
// The corpus type is a pair of:
// - A map of field ids to field values.
// - The serialized buffer of the table.
template <typename T>
class FlatbuffersTableDomainImpl
    : public domain_implementor::DomainBase<
          /*Derived=*/FlatbuffersTableDomainImpl<T>,
          /*ValueType=*/const T*,
          /*CorpusType=*/FlatbuffersTableDomainCorpusType> {
 public:
  using typename FlatbuffersTableDomainImpl::DomainBase::corpus_type;
  using typename FlatbuffersTableDomainImpl::DomainBase::value_type;

  FlatbuffersTableDomainImpl() {
    flatbuffers::Verifier verifier(T::BinarySchema::data(),
                                   T::BinarySchema::size());
    FUZZTEST_INTERNAL_CHECK(reflection::VerifySchemaBuffer(verifier),
                            "Invalid schema for flatbuffers table.");
    auto schema = reflection::GetSchema(T::BinarySchema::data());
    auto table_object =
        schema->objects()->LookupByKey(T::GetFullyQualifiedName());
    inner_ = FlatbuffersTableUntypedDomainImpl{schema, table_object};
  }

  // Initializes the table with random values.
  corpus_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) {
      return *seed;
    }
    // Create new map of field ids to field values
    auto val = inner_->Init(prng);
    // Return corpus value: pair of the map and the serialized buffer.
    return FlatbuffersTableDomainCorpusType{val, {}};
  }

  // Returns the number of fields in the table.
  uint64_t CountNumberOfFields(corpus_type& val) {
    return inner_->CountNumberOfFields(val.untyped_corpus);
  }

  // Mutates the given corpus value.
  void Mutate(corpus_type& val, absl::BitGenRef prng,
              const domain_implementor::MutationMetadata& metadata,
              bool only_shrink) {
    // Modify values in the map.
    inner_->Mutate(val.untyped_corpus, prng, metadata, only_shrink);
  }

  // Converts corpus value into the exact flatbuffer.
  value_type GetValue(const corpus_type& value) const {
    value.buffer = BuildBuffer(value.untyped_corpus);
    return flatbuffers::GetRoot<T>(value.buffer.data());
  }

  // Creates corpus value from the exact flatbuffer.
  std::optional<corpus_type> FromValue(const value_type& value) const {
    auto val = inner_->FromValue((const flatbuffers::Table*)value);
    if (!val.has_value()) return std::nullopt;
    return std::optional(
        FlatbuffersTableDomainCorpusType{*val, BuildBuffer(*val)});
  }

  // Returns the printer for the table.
  auto GetPrinter() const { return Printer{*inner_}; }

  // Returns the parsed corpus value.
  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    auto val = inner_->ParseCorpus(obj);
    if (!val.has_value()) return std::nullopt;
    return std::optional(
        FlatbuffersTableDomainCorpusType{*val, BuildBuffer(*val)});
  }

  // Returns the serialized corpus value.
  IRObject SerializeCorpus(const corpus_type& corpus_value) const {
    return inner_->SerializeCorpus(corpus_value.untyped_corpus);
  }

  // Returns the status of the given corpus value.
  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const {
    return inner_->ValidateCorpusValue(corpus_value.untyped_corpus);
  }

 private:
  std::optional<FlatbuffersTableUntypedDomainImpl> inner_;

  struct Printer {
    const FlatbuffersTableUntypedDomainImpl& inner;

    void PrintCorpusValue(const corpus_type& value,
                          domain_implementor::RawSink out,
                          domain_implementor::PrintMode mode) const {
      inner.GetPrinter().PrintCorpusValue(value.untyped_corpus, out, mode);
    }
  };

  std::vector<uint8_t> BuildBuffer(
      const corpus_type_t<FlatbuffersTableUntypedDomainImpl>& val) const {
    flatbuffers::FlatBufferBuilder builder;
    auto offset = inner_->BuildTable(val, builder);
    builder.Finish(flatbuffers::Offset<flatbuffers::Table>(offset));
    auto buffer =
        std::vector<uint8_t>(builder.GetBufferPointer(),
                             builder.GetBufferPointer() + builder.GetSize());
    return buffer;
  }
};

template <typename T>
class ArbitraryImpl<const T*, std::enable_if_t<is_flatbuffers_table_v<T>>>
    : public FlatbuffersTableDomainImpl<T> {};

}  // namespace fuzztest::internal
#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FLATBUFFERS_DOMAIN_IMPL_H_
