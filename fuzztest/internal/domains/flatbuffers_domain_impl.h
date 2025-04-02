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
#include <initializer_list>
#include <limits>
#include <list>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "absl/base/nullability.h"
#include "absl/base/thread_annotations.h"
#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/synchronization/mutex.h"
#include "flatbuffers/base.h"
#include "flatbuffers/buffer.h"
#include "flatbuffers/flatbuffer_builder.h"
#include "flatbuffers/reflection.h"
#include "flatbuffers/reflection_generated.h"
#include "flatbuffers/string.h"
#include "flatbuffers/struct.h"
#include "flatbuffers/table.h"
#include "flatbuffers/vector.h"
#include "flatbuffers/verifier.h"
#include "./common/logging.h"
#include "./fuzztest/domain_core.h"
#include "./fuzztest/internal/any.h"
#include "./fuzztest/internal/domains/arbitrary_impl.h"
#include "./fuzztest/internal/domains/container_of_impl.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/domain_type_erasure.h"
#include "./fuzztest/internal/domains/element_of_impl.h"
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

template <typename T>
struct FlatbuffersVector64Tag {
  using value_type = T;
};

template <typename T>
struct is_flatbuffers_vector64_tag : std::false_type {};

template <typename T>
struct is_flatbuffers_vector64_tag<FlatbuffersVector64Tag<T>> : std::true_type {
};

template <typename T>
inline constexpr bool is_flatbuffers_vector64_tag_v =
    is_flatbuffers_vector64_tag<T>::value;

template <typename T>
inline constexpr bool is_any_flatbuffers_vector_tag_v =
    is_flatbuffers_vector_tag_v<T> || is_flatbuffers_vector64_tag_v<T>;

template <typename T>
struct flatbuffers_vector_tag_offset;

template <typename T>
struct flatbuffers_vector_tag_offset<FlatbuffersVectorTag<T>> {
  using type = flatbuffers::uoffset_t;
};

template <typename T>
struct flatbuffers_vector_tag_offset<FlatbuffersVector64Tag<T>> {
  using type = flatbuffers::uoffset64_t;
};

template <typename T>
using flatbuffers_vector_tag_offset_t =
    typename flatbuffers_vector_tag_offset<T>::type;

struct FlatbuffersArrayTag;

// Flatbuffers container element type detection.
template <typename T, typename ValueType>
inline constexpr bool is_flatbuffers_container_of_v = []() constexpr {
  if constexpr (is_flatbuffers_vector_tag_v<T> ||
                is_flatbuffers_vector64_tag_v<T>) {
    return std::is_same_v<ValueType, typename T::value_type>;
  } else {
    return false;
  }
}();

struct FlatbuffersTableTag;
struct FlatbuffersStructTag;
struct FlatbuffersUnionTag;

template <typename T>
using IdentityWrapper = T;

// Dynamic to static dispatch visitor pattern.
template <template <typename> typename Wrapper = IdentityWrapper,
          bool in_container = false, typename Visitor>
void VisitFlatbufferField(const reflection::Schema* absl_nonnull schema,
                          const reflection::Field* absl_nonnull field,
                          Visitor&& visitor) {
  const auto type =
      in_container ? field->type()->element() : field->type()->base_type();
  const auto field_index = field->type()->index();
  const bool is_enum = flatbuffers::IsInteger(type) && field_index >= 0;
  switch (type) {
    case reflection::BaseType::Bool:
      std::forward<Visitor>(visitor).template Visit<Wrapper<bool>>(field);
      break;
    case reflection::BaseType::Byte:
      if (is_enum) {
        std::forward<Visitor>(visitor)
            .template Visit<Wrapper<FlatbuffersEnumTag<int8_t>>>(field);
      } else {
        std::forward<Visitor>(visitor).template Visit<Wrapper<int8_t>>(field);
      }
      break;
    case reflection::BaseType::Short:
      if (is_enum) {
        std::forward<Visitor>(visitor)
            .template Visit<Wrapper<FlatbuffersEnumTag<int16_t>>>(field);
      } else {
        std::forward<Visitor>(visitor).template Visit<Wrapper<int16_t>>(field);
      }
      break;
    case reflection::BaseType::Int:
      if (is_enum) {
        std::forward<Visitor>(visitor)
            .template Visit<Wrapper<FlatbuffersEnumTag<int32_t>>>(field);
      } else {
        std::forward<Visitor>(visitor).template Visit<Wrapper<int32_t>>(field);
      }
      break;
    case reflection::BaseType::Long:
      if (is_enum) {
        std::forward<Visitor>(visitor)
            .template Visit<Wrapper<FlatbuffersEnumTag<int64_t>>>(field);
      } else {
        std::forward<Visitor>(visitor).template Visit<Wrapper<int64_t>>(field);
      }
      break;
    case reflection::BaseType::UByte:
      if (is_enum) {
        std::forward<Visitor>(visitor)
            .template Visit<Wrapper<FlatbuffersEnumTag<uint8_t>>>(field);
      } else {
        std::forward<Visitor>(visitor).template Visit<Wrapper<uint8_t>>(field);
      }
      break;
    case reflection::BaseType::UShort:
      if (is_enum) {
        std::forward<Visitor>(visitor)
            .template Visit<Wrapper<FlatbuffersEnumTag<uint16_t>>>(field);
      } else {
        std::forward<Visitor>(visitor).template Visit<Wrapper<uint16_t>>(field);
      }
      break;
    case reflection::BaseType::UInt:
      if (is_enum) {
        std::forward<Visitor>(visitor)
            .template Visit<Wrapper<FlatbuffersEnumTag<uint32_t>>>(field);
      } else {
        std::forward<Visitor>(visitor).template Visit<Wrapper<uint32_t>>(field);
      }
      break;
    case reflection::BaseType::ULong:
      if (is_enum) {
        std::forward<Visitor>(visitor)
            .template Visit<Wrapper<FlatbuffersEnumTag<uint64_t>>>(field);
      } else {
        std::forward<Visitor>(visitor).template Visit<Wrapper<uint64_t>>(field);
      }
      break;
    case reflection::BaseType::Float:
      std::forward<Visitor>(visitor).template Visit<Wrapper<float>>(field);
      break;
    case reflection::BaseType::Double:
      std::forward<Visitor>(visitor).template Visit<Wrapper<double>>(field);
      break;
    case reflection::BaseType::String:
      std::forward<Visitor>(visitor).template Visit<Wrapper<std::string>>(
          field);
      break;
    case reflection::BaseType::Vector:
      if constexpr (in_container) {
        FUZZTEST_LOG(FATAL) << "Nested containers are not supported.";
      } else {
        VisitFlatbufferField<FlatbuffersVectorTag, /*in_container=*/true>(
            schema, field, std::forward<Visitor>(visitor));
      }
      break;
    case reflection::BaseType::Vector64:
      if constexpr (in_container) {
        FUZZTEST_LOG(FATAL) << "Nested containers are not supported.";
      } else {
        VisitFlatbufferField<FlatbuffersVector64Tag, /*in_container=*/true>(
            schema, field, std::forward<Visitor>(visitor));
      }
      break;
    case reflection::BaseType::Array:
      if constexpr (in_container) {
        FUZZTEST_LOG(FATAL) << "Nested containers are not supported.";
      } else {
        std::forward<Visitor>(visitor)
            .template Visit<Wrapper<FlatbuffersArrayTag>>(field);
      }
      break;
    case reflection::BaseType::Obj:
      if (schema->objects()->Get(field_index)->is_struct()) {
        std::forward<Visitor>(visitor)
            .template Visit<Wrapper<FlatbuffersStructTag>>(field);
      } else {
        std::forward<Visitor>(visitor)
            .template Visit<Wrapper<FlatbuffersTableTag>>(field);
      }
      break;
    case reflection::BaseType::Union:
      std::forward<Visitor>(visitor)
          .template Visit<Wrapper<FlatbuffersUnionTag>>(field);
      break;
    case reflection::BaseType::UType:
      // Noop: Union type fields are handled when processing their
      // corresponding union field
      break;
    default:
      FUZZTEST_LOG(FATAL) << "Unsupported base type: "
                          << reflection::EnumNameBaseType(type);
  }
}

// Flatbuffers enum domain implementation.
template <typename Underlying>
class FlatbuffersEnumDomainImpl
    : public domain_implementor::DomainBase<
          /*Derived=*/FlatbuffersEnumDomainImpl<Underlying>,
          /*ValueType=*/Underlying,
          /*CorpusType=*/ElementOfImplCorpusType> {
 public:
  using typename FlatbuffersEnumDomainImpl::DomainBase::corpus_type;
  using typename FlatbuffersEnumDomainImpl::DomainBase::value_type;

  explicit FlatbuffersEnumDomainImpl(const reflection::Enum* enum_def)
      : enum_def_(enum_def), inner_(GetEnumValues(enum_def, {})) {}

  FlatbuffersEnumDomainImpl& WithExcludedValues(
      std::initializer_list<value_type> excluded_values) {
    excluded_values_ = {excluded_values.begin(), excluded_values.end()};
    inner_ =
        ElementOfImpl<Underlying>(GetEnumValues(enum_def_, excluded_values));
    return *this;
  }

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
  absl::flat_hash_set<value_type> excluded_values_;
  ElementOfImpl<Underlying> inner_;

  static std::vector<value_type> GetEnumValues(
      const reflection::Enum* enum_def,
      std::initializer_list<value_type> excluded_values) {
    std::vector<value_type> values;
    values.reserve(enum_def->values()->size());
    for (const auto* value : *enum_def->values()) {
      FUZZTEST_CHECK(value->value() >= std::numeric_limits<value_type>::min() &&
                     value->value() <= std::numeric_limits<value_type>::max())
          << "Enum value from reflection is out of range for the target type.";
      if (std::find(excluded_values.begin(), excluded_values.end(),
                    value->value()) == excluded_values.end()) {
        values.push_back(static_cast<value_type>(value->value()));
      }
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
      : schema_(schema), object_(object) {
    for (const auto* field : *object_->fields()) {
      fields_by_id_[field->id()] = field;
    }
  }

  virtual ~FlatbuffersUntypedObjectDomainBase() = default;

  FlatbuffersUntypedObjectDomainBase(
      const FlatbuffersUntypedObjectDomainBase& other)
      : DomainBase(other),
        schema_(other.schema_),
        object_(other.object_),
        fields_by_id_(other.fields_by_id_) {
    absl::MutexLock l(mutex_);
    absl::MutexLock l_other(other.mutex_);
    domains_ = other.domains_;
  }

  FlatbuffersUntypedObjectDomainBase& operator=(
      const FlatbuffersUntypedObjectDomainBase& other) {
    schema_ = other.schema_;
    object_ = other.object_;
    fields_by_id_ = other.fields_by_id_;
    absl::MutexLock l(mutex_);
    absl::MutexLock l_other(other.mutex_);
    domains_ = other.domains_;
    DomainBase::operator=(other);
    return *this;
  }

  FlatbuffersUntypedObjectDomainBase(FlatbuffersUntypedObjectDomainBase&& other)
      : schema_(other.schema_),
        object_(other.object_),
        fields_by_id_(std::move(other.fields_by_id_)) {
    absl::MutexLock l(mutex_);
    absl::MutexLock l_other(other.mutex_);
    domains_ = std::move(other.domains_);
    DomainBase::operator=(other);
  }

  FlatbuffersUntypedObjectDomainBase& operator=(
      FlatbuffersUntypedObjectDomainBase&& other) {
    schema_ = other.schema_;
    object_ = other.object_;
    fields_by_id_ = std::move(other.fields_by_id_);
    absl::MutexLock l(mutex_);
    absl::MutexLock l_other(other.mutex_);
    domains_ = std::move(other.domains_);
    DomainBase::operator=(std::move(other));
    return *this;
  }

  // Initializes the corpus value.
  corpus_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) {
      return *seed;
    }
    corpus_type val;
    for (const auto& [_, field] : fields_by_id_) {
      VisitFlatbufferField(schema_, field,
                           InitializeVisitor{Self(), prng, val});
    }
    return val;
  }

  // Mutates the corpus value.
  void Mutate(corpus_type& val, absl::BitGenRef prng,
              const domain_implementor::MutationMetadata& metadata,
              bool only_shrink) {
    auto field_count = CountNumberOfFields(val);
    if (field_count == 0) return;
    auto selected_field_index = absl::Uniform(prng, 1ul, field_count + 1);

    MutateSelectedField(val, prng, metadata, only_shrink, selected_field_index);
  }

  // Counts the number of fields that can be mutated.
  // Returns the number of fields in the flattened tree for supported field
  // types.
  uint64_t CountNumberOfFields(corpus_type& val) {
    uint64_t field_count = 0;
    for (const auto& [_, field] : fields_by_id_) {
      VisitFlatbufferField(
          schema_, field,
          CountNumberOfMutableFieldsVisitor{Self(), field_count, val});
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
    uint64_t fields_count = CountNumberOfFields(val);
    if (fields_count < selected_field_index) {
      return fields_count;
    }
    for (const auto& [_, field] : fields_by_id_) {
      VisitFlatbufferField(schema_, field,
                           MutateSelectedFieldVisitor{
                               Self(), prng, metadata, selected_field_index,
                               only_shrink, val, field_counter});
      if (field_counter >= selected_field_index) {
        return field_counter;
      }
    }
    return field_counter;
  }

  auto GetPrinter() const { return Printer{Self()}; }

  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const {
    for (const auto& [id, field_corpus] : corpus_value) {
      const reflection::Field* absl_nullable field = GetFieldById(id);
      if (field == nullptr) {
        return absl::InvalidArgumentError(
            absl::StrCat("Field id ", id, " is not found in the object."));
      }
      absl::Status result;
      VisitFlatbufferField(schema_, field,
                           ValidateVisitor{Self(), field_corpus, result});
      if (!result.ok()) return result;
    }
    return absl::OkStatus();
  }

  value_type GetValue(const corpus_type& value) const {
    FUZZTEST_LOG(FATAL)
        << "GetValue is not supported for the untyped Flatbuffers domain.";
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
                           ParseVisitor{Self(), (*pair_subs)[1], inner_parsed});
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
          SerializeVisitor{Self(), field_corpus, pair_subs.emplace_back()});
    }
    return out;
  }

 protected:
  const reflection::Schema* schema_;
  const reflection::Object* object_;
  absl::btree_map<typename corpus_type::key_type, const reflection::Field*>
      fields_by_id_;
  mutable absl::Mutex mutex_;
  mutable absl::flat_hash_map<
      decltype(static_cast<reflection::Field*>(nullptr)->id()), CopyableAny>
      domains_ ABSL_GUARDED_BY(mutex_);

  // Helper function to downcast to the derived type
  Derived& Self() { return static_cast<Derived&>(*this); }
  const Derived& Self() const { return static_cast<const Derived&>(*this); }

  bool IsSupportedField(const reflection::Field* absl_nonnull field) const {
    auto base_type = field->type()->base_type();
    // Union types are handled as part of the union field.
    if (base_type == reflection::BaseType::UType) return false;
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
    // TODO: Support Array fields.
    return false;
  }

  const reflection::Field* absl_nullable GetFieldById(
      typename corpus_type::key_type id) const {
    if (auto it = fields_by_id_.find(id); it != fields_by_id_.end()) {
      return it->second;
    }
    return nullptr;
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
    absl::MutexLock l(mutex_);
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
    const Derived& derived;
    const GenericDomainCorpusType& field_corpus;
    domain_implementor::RawSink sink;
    domain_implementor::PrintMode mode;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = derived.template GetCachedDomain<T>(field);
      absl::Format(sink, "%s: ", field->name()->c_str());
      if constexpr (is_flatbuffers_container_of_v<T, uint8_t> ||
                    is_flatbuffers_container_of_v<
                        T, FlatbuffersEnumTag<uint8_t>>) {
        // Handle the case where the field is a vector<uint8_t> or
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

        if constexpr (is_flatbuffers_container_of_v<T, uint8_t>) {
          auto inner_corpus = object_corpus.GetAs<corpus_type_t<
              ContainerOfImpl<std::vector<uint8_t>, ArbitraryImpl<uint8_t>>>>();
          auto inner_domain = Arbitrary<uint8_t>();
          auto printer = ContainerPrinter<
              ContainerOfImpl<std::vector<uint8_t>, ArbitraryImpl<uint8_t>>,
              ArbitraryImpl<uint8_t>>{inner_domain};
          printer.PrintCorpusValue(inner_corpus, sink, mode);
        } else {  // container of FlatbuffersEnumTag<uint8_t>
          auto inner_corpus = object_corpus.GetAs<corpus_type_t<ContainerOfImpl<
              std::vector<uint8_t>, FlatbuffersEnumDomainImpl<uint8_t>>>>();
          auto enum_object =
              derived.schema_->enums()->Get(field->type()->index());
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
    const Derived& derived;

    void PrintCorpusValue(const corpus_type& value,
                          domain_implementor::RawSink out,
                          domain_implementor::PrintMode mode) const {
      std::vector<typename corpus_type::key_type> field_ids;
      field_ids.reserve(value.size());
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
        const reflection::Field* absl_nullable field = derived.GetFieldById(id);
        if (field == nullptr) {
          absl::Format(out, "<unknown field: %d>", id);
        } else {
          VisitFlatbufferField(
              derived.schema_, field,
              PrinterVisitor{derived, value.at(id), out, mode});
        }
        first = false;
      }
      absl::Format(out, "}");
    }
  };

  struct InitializeVisitor {
    const Derived& derived;
    absl::BitGenRef prng;
    corpus_type& corpus;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = derived.template GetCachedDomain<T>(field);
      corpus[field->id()] = domain.Init(prng);
    }
  };

  struct CountNumberOfMutableFieldsVisitor {
    const Derived& derived;
    uint64_t& field_count;
    corpus_type& corpus_value;
    const bool only_shrink = false;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      if (!derived.IsSupportedField(field)) return;
      auto it = corpus_value.find(field->id());
      if (only_shrink && it == corpus_value.end()) return;

      field_count++;

      if constexpr (std::is_same_v<T, FlatbuffersTableTag> ||
                    std::is_same_v<T, FlatbuffersStructTag> ||
                    std::is_same_v<T, FlatbuffersUnionTag> ||
                    is_flatbuffers_container_of_v<T, FlatbuffersTableTag> ||
                    is_flatbuffers_container_of_v<T, FlatbuffersStructTag> ||
                    is_flatbuffers_container_of_v<T, FlatbuffersUnionTag>) {
        if (it == corpus_value.end()) return;
        auto& domain = derived.template GetCachedDomain<T>(field);
        // Count the fields in the corpus for domains that support it.
        field_count += domain.CountNumberOfFields(it->second);
      }
    }
  };

  struct MutateSelectedFieldVisitor {
    const Derived& derived;
    absl::BitGenRef prng;
    const domain_implementor::MutationMetadata& metadata;
    const uint64_t selected_field_index;
    const bool only_shrink;
    corpus_type& corpus_value;
    uint64_t& field_counter;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      if (!derived.IsSupportedField(field)) return;
      auto it = corpus_value.find(field->id());
      if (only_shrink && it == corpus_value.end()) return;

      field_counter++;
      auto& domain = derived.template GetCachedDomain<T>(field);
      if (field_counter == selected_field_index) {
        if (it == corpus_value.end()) {
          it = corpus_value.try_emplace(field->id(), domain.Init(prng)).first;
        }
        domain.Mutate(it->second, prng, metadata, only_shrink);
        return;
      }

      if constexpr (std::is_same_v<T, FlatbuffersTableTag> ||
                    std::is_same_v<T, FlatbuffersStructTag> ||
                    std::is_same_v<T, FlatbuffersUnionTag> ||
                    is_flatbuffers_container_of_v<T, FlatbuffersTableTag> ||
                    is_flatbuffers_container_of_v<T, FlatbuffersStructTag> ||
                    is_flatbuffers_container_of_v<T, FlatbuffersUnionTag>) {
        if (it == corpus_value.end()) return;
        field_counter +=
            domain.MutateSelectedField(it->second, prng, metadata, only_shrink,
                                       selected_field_index - field_counter);
      }
    }
  };

  struct ParseVisitor {
    const Derived& derived;
    const IRObject& ir_object;
    std::optional<GenericDomainCorpusType>& corpus;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = derived.template GetCachedDomain<T>(field);
      corpus = domain.ParseCorpus(ir_object);
    }
  };

  struct SerializeVisitor {
    const Derived& derived;
    const GenericDomainCorpusType& corpus;
    IRObject& ir_object;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = derived.template GetCachedDomain<T>(field);
      ir_object = domain.SerializeCorpus(corpus);
    }
  };

  struct ValidateVisitor {
    const Derived& derived;
    const GenericDomainCorpusType& inner_corpus;
    absl::Status& status;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = derived.template GetCachedDomain<T>(field);
      status = domain.ValidateCorpusValue(inner_corpus);
      if (!status.ok()) {
        status = Prefix(status, absl::StrCat("Invalid value for field ",
                                             field->name()->c_str()));
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
    FUZZTEST_CHECK(struct_object->is_struct())
        << "Object must be a struct type.";
  }

  // Converts the struct pointer to a corpus value.
  std::optional<corpus_type> FromValue(const value_type& value) const;

  // Builds the struct in a builder.
  std::optional<flatbuffers::uoffset_t> BuildValue(
      const corpus_type& value,
      flatbuffers::FlatBufferBuilder64& builder) const;

  // Builds the struct in a buffer.
  void BuildValue(const corpus_type& value, uint8_t* buf) const;

 private:
  struct FromValueVisitor {
    const FlatbuffersStructUntypedDomainImpl& self;
    value_type value;
    corpus_type& out;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      [[maybe_unused]]
      reflection::BaseType base_type = field->type()->base_type();
      auto& domain = self.GetCachedDomain<T>(field);
      std::optional<corpus_type_t<std::decay_t<decltype(domain)>>> inner_corpus;

      if constexpr (is_flatbuffers_enum_tag_v<T>) {
        auto inner_value = value->GetField<typename T::type>(field->offset());
        inner_corpus = domain.FromValue(inner_value);
      } else if constexpr (std::is_integral_v<T> ||
                           std::is_floating_point_v<T>) {
        auto inner_value = value->GetField<T>(field->offset());
        inner_corpus = domain.FromValue(inner_value);
      } else if constexpr (std::is_same_v<T, FlatbuffersStructTag>) {
        auto inner_value =
            value->GetStruct<const flatbuffers::Struct*>(field->offset());
        inner_corpus = domain.FromValue(inner_value);
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
    void Visit(const reflection::Field* absl_nonnull field) {
      [[maybe_unused]]
      reflection::BaseType base_type = field->type()->base_type();
      auto& domain = self.GetCachedDomain<T>(field);
      if constexpr (is_flatbuffers_enum_tag_v<T> || std::is_integral_v<T> ||
                    std::is_floating_point_v<T>) {
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
        auto inner_corpus_value =
            corpus_value.at(field->id())
                .GetAs<FlatbuffersStructUntypedDomainImpl::corpus_type>();
        FlatbuffersStructUntypedDomainImpl sub_domain(self.schema_, sub_object);
        for (const auto& [_, nested_field] : sub_domain.fields_by_id_) {
          VisitFlatbufferField(sub_domain.schema_, nested_field,
                               BuildValueVisitor{sub_domain, inner_corpus_value,
                                                 struct_ptr + field->offset()});
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersArrayTag>) {
        // TODO (b/405938558): Implement array support.
      }
    }
  };
};

// From flatbuffers documentation:
// Unions are encoded as the combination of two fields: an enum representing the
// union choice and the offset to the actual element.
// The type of the enum is always uint8_t as generated by the flatbuffers
// compiler.
using FlatbuffersUnionTypeDomainImpl = FlatbuffersEnumDomainImpl<uint8_t>;

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
                             const reflection::Enum* union_def);

  FlatbuffersUnionDomainImpl(const FlatbuffersUnionDomainImpl& other);
  FlatbuffersUnionDomainImpl(FlatbuffersUnionDomainImpl&& other);
  FlatbuffersUnionDomainImpl& operator=(
      const FlatbuffersUnionDomainImpl& other);
  FlatbuffersUnionDomainImpl& operator=(FlatbuffersUnionDomainImpl&& other);

  // Initializes the corpus value.
  corpus_type Init(absl::BitGenRef prng);

  // Mutates the corpus value.
  void Mutate(corpus_type& corpus_value, absl::BitGenRef prng,
              const domain_implementor::MutationMetadata& metadata,
              bool only_shrink);

  uint64_t CountNumberOfFields(corpus_type& corpus_value);

  uint64_t MutateSelectedField(
      corpus_type& corpus_value, absl::BitGenRef prng,
      const domain_implementor::MutationMetadata& metadata, bool only_shrink,
      uint64_t selected_field_index);

  auto GetPrinter() const { return Printer{*this}; }

  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const;

  // UNSUPPORTED: Flatbuffers unions user values are not supported.
  value_type GetValue(const corpus_type& corpus_value) const {
    FUZZTEST_LOG(FATAL) << "GetValue is not supported for unions.";
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
      flatbuffers::FlatBufferBuilder64& builder) const;

  // Returns the domain for the given enum value.
  template <typename T>
  auto& GetCachedDomain(const reflection::EnumVal& enum_value) const {
    using DomainT = decltype(GetDefaultDomainForType<T>(enum_value));
    absl::MutexLock l(mutex_);
    auto [it, inserted] =
        domains_.try_emplace(enum_value.value(), std::in_place_type<DomainT>,
                             GetDefaultDomainForType<T>(enum_value));
    return it->second.template GetAs<DomainT>();
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
                      flatbuffers::FlatBufferBuilder64& builder) const;

  // Returns the domain for the given field.
  // The domain is cached, and the same instance is returned for the same
  // field.
  template <typename T>
  auto& GetCachedDomain(const reflection::Field* absl_nonnull field) const {
    auto get_optional_domain = [this, field]() {
      auto inner_domain = GetDefaultDomain<T>(schema_, field);
      auto optional_domain = OptionalOf(inner_domain);
      if (!field->optional() || field->required()) {
        optional_domain.SetWithoutNull();
      }
      if constexpr (std::is_same_v<T, FlatbuffersUnionTag>) {
        auto union_type = schema_->enums()->Get(field->type()->index());
        // If the union has only one type (NONE), we can always return null.
        if (union_type->values()->size() == 1) {
          optional_domain.SetAlwaysNull();
        }
      }
      return Domain<value_type_t<decltype(optional_domain)>>{optional_domain};
    };

    using DomainT = decltype(get_optional_domain());
    // Do the operation under a lock to prevent race conditions in `const`
    // methods.
    absl::MutexLock l(mutex_);
    auto it = domains_.find(field->id());
    if (it == domains_.end()) {
      it = domains_
               .try_emplace(field->id(), std::in_place_type<DomainT>,
                            get_optional_domain())
               .first;
    }
    return it->second.template GetAs<DomainT>();
  }

  struct FromValueVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    value_type user_value;
    corpus_type& corpus_value;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      [[maybe_unused]]
      reflection::BaseType base_type = field->type()->base_type();
      auto& domain = self.GetCachedDomain<T>(field);
      using InnerDomain = std::decay_t<decltype(domain)>;
      value_type_t<InnerDomain> inner_value;

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
          if (field->offset64()) {
            inner_value = std::optional(
                user_value->GetPointer64<flatbuffers::String*>(field->offset())
                    ->str());
          } else {
            inner_value = std::optional(
                user_value->GetPointer<flatbuffers::String*>(field->offset())
                    ->str());
          }
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersTableTag>) {
        auto sub_object = self.schema_->objects()->Get(field->type()->index());
        FUZZTEST_CHECK(base_type == reflection::BaseType::Obj &&
                       !sub_object->is_struct())
            << "Field must be a table type.";
        inner_value =
            user_value->GetPointer<const flatbuffers::Table*>(field->offset());
      } else if constexpr (std::is_same_v<T, FlatbuffersStructTag>) {
        inner_value =
            user_value->GetStruct<const flatbuffers::Struct*>(field->offset());
      } else if constexpr (is_any_flatbuffers_vector_tag_v<T>) {
        using ElementType = typename T::value_type;
        if (user_value->CheckField(field->offset())) {
          inner_value = typename value_type_t<InnerDomain>::value_type{};
          VisitVector<ElementType, std::decay_t<decltype(domain)>,
                      flatbuffers_vector_tag_offset_t<T>>(field, inner_value);
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersUnionTag>) {
        constexpr char kUnionTypeFieldSuffix[] = "_type";
        auto enumdef = self.schema_->enums()->Get(field->type()->index());
        auto type_field = self.object_->fields()->LookupByKey(
            absl::StrCat(field->name()->c_str(), kUnionTypeFieldSuffix)
                .c_str());
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

      if (inner_value) {
        auto inner = domain.FromValue(inner_value);
        if (inner) {
          corpus_value[field->id()] = *std::move(inner);
        }
      }
    }

    // Helper to get the flatbuffers vector type.
    template <typename Element, typename Offset>
    struct FlatbuffersVectorType {
     private:
      static_assert(std::is_same_v<Offset, flatbuffers::uoffset_t> ||
                        std::is_same_v<Offset, flatbuffers::uoffset64_t>,
                    "Offset must be uoffset_t or uoffset64_t.");
      static_assert(std::is_arithmetic_v<Element> ||
                        is_flatbuffers_enum_tag_v<Element> ||
                        std::is_same_v<Element, std::string> ||
                        std::is_same_v<Element, FlatbuffersTableTag> ||
                        std::is_same_v<Element, FlatbuffersStructTag> ||
                        std::is_same_v<Element, FlatbuffersUnionTag>,
                    "Unsupported vector element type.");

      static constexpr auto get_flatbuffers_type_pointer() {
        if constexpr (std::is_integral_v<Element> ||
                      std::is_floating_point_v<Element>) {
          return static_cast<flatbuffers::Vector<Element, Offset>*>(nullptr);
        } else if constexpr (is_flatbuffers_enum_tag_v<Element>) {
          return static_cast<
              flatbuffers::Vector<typename Element::type, Offset>*>(nullptr);
        } else if constexpr (std::is_same_v<Element, std::string>) {
          return static_cast<flatbuffers::Vector<
              flatbuffers::Offset<flatbuffers::String>, Offset>*>(nullptr);
        } else if constexpr (std::is_same_v<Element, FlatbuffersTableTag>) {
          return static_cast<flatbuffers::Vector<
              flatbuffers::Offset<flatbuffers::Table>, Offset>*>(nullptr);
        } else if constexpr (std::is_same_v<Element, FlatbuffersStructTag>) {
          // Struct vector are serialized inline and accessed as bytes.
          return static_cast<const flatbuffers::Vector<uint8_t>*>(nullptr);
        } else if constexpr (std::is_same_v<Element, FlatbuffersUnionTag>) {
          return static_cast<flatbuffers::Vector<flatbuffers::Offset<void>>*>(
              nullptr);
        }
      }

     public:
      using type =
          std::remove_pointer_t<decltype(get_flatbuffers_type_pointer())>;
    };

    template <typename Element, typename Domain, typename Offset>
    void VisitVector(const reflection::Field* field,
                     value_type_t<Domain>& vector_corpus) const {
      using FlatbuffersVector =
          typename FlatbuffersVectorType<Element, Offset>::type;
      const FlatbuffersVector* vec;
      if constexpr (std::is_same_v<Offset, flatbuffers::uoffset64_t>) {
        vec =
            user_value->GetPointer64<const FlatbuffersVector*>(field->offset());
      } else {
        vec = user_value->GetPointer<const FlatbuffersVector*>(field->offset());
      }
      vector_corpus->reserve(vec->size());
      if constexpr (std::is_same_v<Element, FlatbuffersUnionTag>) {
        constexpr char kUnionTypeFieldSuffix[] = "_type";
        auto type_field = self.object_->fields()->LookupByKey(
            absl::StrCat(field->name()->c_str(), kUnionTypeFieldSuffix)
                .c_str());
        FUZZTEST_CHECK(type_field != nullptr) << "Union type field not found.";
        const auto* type_vec =
            user_value->GetPointer<const flatbuffers::Vector<uint8_t>*>(
                type_field->offset());
        for (decltype(vec->size()) i = 0; i < vec->size(); ++i) {
          vector_corpus->push_back({type_vec->Get(i), vec->Get(i)});
        }
      } else {
        for (decltype(vec->size()) i = 0; i < vec->size(); ++i) {
          if constexpr (std::is_same_v<Element, std::string>) {
            vector_corpus->push_back(vec->Get(i)->str());
          } else if constexpr (std::is_same_v<Element, FlatbuffersStructTag>) {
            const reflection::Object* object_def =
                self.schema_->objects()->Get(field->type()->index());
            // Struct vector are serialized inline.
            const uint8_t* struct_data_ptr =
                vec->Data() + i * object_def->bytesize();
            vector_corpus->push_back(
                reinterpret_cast<const flatbuffers::Struct*>(struct_data_ptr));
          } else {
            vector_corpus->push_back(vec->Get(i));
          }
        }
      }
    }
  };

  // Create out-of-line table fields, see `BuildTable` for details.
  struct TableFieldBuilderVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    flatbuffers::FlatBufferBuilder64& builder;
    absl::flat_hash_map<typename corpus_type::key_type,
                        flatbuffers::uoffset64_t>& offsets;
    const typename corpus_type::mapped_type& corpus_value;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      if constexpr (std::is_same_v<T, std::string>) {
        auto& domain = self.GetCachedDomain<T>(field);
        auto user_value = domain.GetValue(corpus_value);
        if (user_value.has_value()) {
          flatbuffers::uoffset64_t offset;
          if (field->offset64()) {
            offset = builder
                         .CreateString<flatbuffers::Offset64>(
                             user_value->data(), user_value->size())
                         .o;
          } else {
            offset =
                builder.CreateString(user_value->data(), user_value->size()).o;
          }
          offsets.insert({field->id(), offset});
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersTableTag>) {
        FlatbuffersTableUntypedDomainImpl inner_domain(
            self.schema_, self.schema_->objects()->Get(field->type()->index()));
        auto optional_corpus =
            corpus_value
                .GetAs<std::variant<std::monostate, GenericDomainCorpusType>>();
        if (std::holds_alternative<GenericDomainCorpusType>(optional_corpus)) {
          auto inner_corpus = std::get<GenericDomainCorpusType>(optional_corpus)
                                  .GetAs<corpus_type>();
          auto offset = inner_domain.BuildTable(inner_corpus, builder);
          offsets.insert({field->id(), offset});
        }
        // Else if the variant is std::monostate the optional field is null and
        // there is no table to build.
      } else if constexpr (is_any_flatbuffers_vector_tag_v<T>) {
        VisitVector<typename T::value_type, flatbuffers_vector_tag_offset_t<T>>(
            field, self.GetCachedDomain<T>(field));
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
    template <typename Element, typename Offset,
              int&... ExplicitArgumentBarrier, typename Domain>
    void VisitVector(const reflection::Field* field,
                     const Domain& domain) const {
      if constexpr (std::is_integral_v<Element> ||
                    std::is_floating_point_v<Element> ||
                    is_flatbuffers_enum_tag_v<Element>) {
        auto value = domain.GetValue(corpus_value);
        if (!value) {
          if (field->optional()) {
            return;
          }
          // Handle case where value is std::nullopt but field is required.
          // Create an empty vector of the appropriate type.
          value = typename decltype(value)::value_type{};
        }
        if constexpr (std::is_same_v<Offset, flatbuffers::uoffset_t>) {
          offsets.insert({field->id(), builder.CreateVector(*value).o});
        } else {
          if constexpr (std::is_same_v<Element, bool>) {
            // Workaround for missing overload for CreateVector64(const
            // std::vector<T>&)
            builder.StartVector<uint8_t, flatbuffers::Offset64>(value->size());
            for (auto i = value->size(); i > 0;) {
              builder.PushElement(static_cast<uint8_t>(value->at(--i)));
            }
            auto offset =
                builder.EndVector<flatbuffers::uoffset64_t,
                                  flatbuffers::uoffset64_t>(value->size());
            offsets.insert({field->id(), offset});
          } else {
            offsets.insert({field->id(), builder.CreateVector64(*value).o});
          }
        }
      } else if constexpr (std::is_same_v<Element, FlatbuffersTableTag> ||
                           std::is_same_v<Element, FlatbuffersStructTag>) {
        auto opt_corpus = corpus_value.template GetAs<
            std::variant<std::monostate, GenericDomainCorpusType>>();
        if (std::holds_alternative<std::monostate>(opt_corpus)) {
          return;
        }
        auto container_corpus = std::get<GenericDomainCorpusType>(opt_corpus)
                                    .GetAs<std::list<corpus_type>>();
        auto sub_object = self.schema_->objects()->Get(field->type()->index());
        if constexpr (std::is_same_v<Element, FlatbuffersTableTag>) {
          std::vector<flatbuffers::Offset<flatbuffers::Table>> vec_offsets;
          FlatbuffersTableUntypedDomainImpl domain(self.schema_, sub_object);
          vec_offsets.reserve(container_corpus.size());
          for (auto& inner_corpus : container_corpus) {
            auto offset = domain.BuildTable(inner_corpus, builder);
            vec_offsets.push_back(offset);
          }
          offsets.insert({field->id(), builder.CreateVector(vec_offsets).o});
        } else {
          uint8_t* vec_ptr = nullptr;
          FlatbuffersStructUntypedDomainImpl inner_domain(self.schema_,
                                                          sub_object);
          auto vec_offset = builder.CreateUninitializedVector(
              container_corpus.size(), sub_object->bytesize(),
              sub_object->minalign(), &vec_ptr);
          size_t i = 0;
          for (const auto& inner_corpus : container_corpus) {
            uint8_t* current_struct_ptr = vec_ptr + i * sub_object->bytesize();
            inner_domain.BuildValue(inner_corpus, current_struct_ptr);
            ++i;
          }
          offsets.insert({field->id(), vec_offset});
        }
      } else if constexpr (std::is_same_v<Element, std::string>) {
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
      } else if constexpr (std::is_same_v<Element, FlatbuffersUnionTag>) {
        const reflection::Enum* union_type =
            self.schema_->enums()->Get(field->type()->index());
        FlatbuffersUnionDomainImpl domain{self.schema_, union_type};
        constexpr char kUnionTypeFieldSuffix[] = "_type";
        const reflection::Field* type_field =
            self.object_->fields()->LookupByKey(
                absl::StrCat(field->name()->c_str(), kUnionTypeFieldSuffix)
                    .c_str());

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
    }
  };

  // Create complete table: store "inline fields" values inline, and store
  // just offsets for "out-of-line fields". See `BuildTable` for details.
  struct TableBuilderVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    flatbuffers::FlatBufferBuilder64& builder;
    absl::flat_hash_map<typename corpus_type::key_type,
                        flatbuffers::uoffset64_t>& offsets;
    const typename corpus_type::value_type::second_type& corpus_value;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
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
                           is_any_flatbuffers_vector_tag_v<T>) {
        // "Out-of-line field". Store just offset.
        if constexpr (is_flatbuffers_container_of_v<T, FlatbuffersUnionTag>) {
          constexpr char kUnionTypeFieldSuffix[] = "_type";
          const reflection::Field* type_field =
              self.object_->fields()->LookupByKey(
                  absl::StrCat(field->name()->c_str(), kUnionTypeFieldSuffix)
                      .c_str());
          if (auto it = offsets.find(type_field->id()); it != offsets.end()) {
            builder.AddOffset(type_field->offset(),
                              flatbuffers::Offset<>(it->second));
          }
        }
        if (auto it = offsets.find(field->id()); it != offsets.end()) {
          if (field->offset64()) {
            builder.AddOffset(field->offset(),
                              flatbuffers::Offset64<>(it->second));
          } else {
            builder.AddOffset(field->offset(),
                              flatbuffers::Offset<>(it->second));
          }
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
                  absl::StrCat(field->name()->c_str(), kUnionTypeFieldSuffix)
                      .c_str());
          auto opt_corpus = corpus_value.GetAs<
              std::variant<std::monostate, GenericDomainCorpusType>>();
          if (std::holds_alternative<std::monostate>(opt_corpus)) {
            return;
          }
          auto inner_corpus = std::get<GenericDomainCorpusType>(opt_corpus)
                                  .GetAs<corpus_type_t<decltype(domain)>>();
          uint8_t type_value = domain.GetType(inner_corpus);
          builder.AddElement<uint8_t>(type_field->offset(), type_value, 0);
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

  if constexpr (std::is_same_v<T, FlatbuffersArrayTag>) {
    // TODO: support arrays.
    return placeholder;
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
  } else if constexpr (is_any_flatbuffers_vector_tag_v<T>) {
    auto elem_domain = GetDefaultDomain<typename T::value_type>(schema, field);
    return VectorOf(elem_domain);
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
    FUZZTEST_CHECK(reflection::VerifySchemaBuffer(verifier))
        << "Invalid schema for flatbuffers table.";
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

  uint64_t MutateSelectedField(
      corpus_type& val, absl::BitGenRef prng,
      const domain_implementor::MutationMetadata& metadata, bool only_shrink,
      uint64_t selected_field_index) {
    return inner_->MutateSelectedField(val.untyped_corpus, prng, metadata,
                                       only_shrink, selected_field_index);
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
    flatbuffers::FlatBufferBuilder64 builder;
    const uint32_t offset = inner_->BuildTable(value.untyped_corpus, builder);
    builder.Finish(flatbuffers::Offset<flatbuffers::Table>(offset));
    value.buffer =
        std::vector<uint8_t>(builder.GetBufferPointer(),
                             builder.GetBufferPointer() + builder.GetSize());
    return flatbuffers::GetRoot<T>(value.buffer.data());
  }

  // Creates corpus value from the exact flatbuffer.
  std::optional<corpus_type> FromValue(const value_type& value) const {
    auto val = inner_->FromValue((const flatbuffers::Table*)value);
    if (!val.has_value()) return std::nullopt;
    return std::optional(FlatbuffersTableDomainCorpusType{*val, {}});
  }

  // Returns the printer for the table.
  auto GetPrinter() const { return Printer{*inner_}; }

  // Returns the parsed corpus value.
  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    auto val = inner_->ParseCorpus(obj);
    if (!val.has_value()) return std::nullopt;
    return std::optional(FlatbuffersTableDomainCorpusType{*val, {}});
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
};

template <typename T>
class ArbitraryImpl<const T*, std::enable_if_t<is_flatbuffers_table_v<T>>>
    : public FlatbuffersTableDomainImpl<T> {};

}  // namespace fuzztest::internal
#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FLATBUFFERS_DOMAIN_IMPL_H_
