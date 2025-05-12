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
#include "absl/random/distributions.h"
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
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/domain_type_erasure.h"
#include "./fuzztest/internal/domains/element_of_impl.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/status.h"

namespace fuzztest::internal {

template <typename Underlying,
          typename = std::enable_if_t<std::is_integral_v<Underlying> &&
                                      !std::is_same_v<Underlying, bool>>>

//
// Flatbuffers enum detection.
//
struct FlatbuffersEnumTag {
  using type = Underlying;
};

template <typename T>
struct is_flatbuffers_enum_tag : std::false_type {};

template <typename Underlying>
struct is_flatbuffers_enum_tag<FlatbuffersEnumTag<Underlying>>
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

struct FlatbuffersArrayTag;
struct FlatbuffersTableTag;
struct FlatbuffersStructTag;
struct FlatbuffersUnionTag;

// Dynamic to static dispatch visitor pattern for flatbuffers vector elements.
template <typename Visitor>
auto VisitFlatbufferVectorElementField(const reflection::Schema* schema,
                                       const reflection::Field* field,
                                       Visitor visitor) {
  auto field_index = field->type()->index();
  auto element_type = field->type()->element();
  switch (element_type) {
    case reflection::BaseType::Bool:
      visitor.template Visit<FlatbuffersVectorTag<bool>>(field);
      break;
    case reflection::BaseType::Byte:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<int8_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<int8_t>>(field);
      }
      break;
    case reflection::BaseType::Short:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<int16_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<int16_t>>(field);
      }
      break;
    case reflection::BaseType::Int:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<int32_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<int32_t>>(field);
      }
      break;
    case reflection::BaseType::Long:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<int64_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<int64_t>>(field);
      }
      break;
    case reflection::BaseType::UByte:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<uint8_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<uint8_t>>(field);
      }
      break;
    case reflection::BaseType::UShort:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<uint16_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<uint16_t>>(field);
      }
      break;
    case reflection::BaseType::UInt:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<uint32_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<uint32_t>>(field);
      }
      break;
    case reflection::BaseType::ULong:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<uint64_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<uint64_t>>(field);
      }
      break;
    case reflection::BaseType::Float:
      visitor.template Visit<FlatbuffersVectorTag<float>>(field);
      break;
    case reflection::BaseType::Double:
      visitor.template Visit<FlatbuffersVectorTag<double>>(field);
      break;
    case reflection::BaseType::String:
      visitor.template Visit<FlatbuffersVectorTag<std::string>>(field);
      break;
    case reflection::BaseType::Obj: {
      auto sub_object = schema->objects()->Get(field_index);
      if (sub_object->is_struct()) {
        visitor.template Visit<FlatbuffersVectorTag<FlatbuffersStructTag>>(
            field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<FlatbuffersTableTag>>(
            field);
      }
      break;
    }
    case reflection::BaseType::Union:
      visitor.template Visit<FlatbuffersVectorTag<FlatbuffersUnionTag>>(field);
      break;
    case reflection::BaseType::UType:
      // Noop: Union types are visited at the same time as their corresponding
      // union values.
      break;
    default:  // Vector of vectors and vector of arrays are not supported.
      FUZZTEST_INTERNAL_CHECK(false, "Unsupported vector base type");
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
      VisitFlatbufferVectorElementField<Visitor>(schema, field, visitor);
      break;
    case reflection::BaseType::Array:
      visitor.template Visit<FlatbuffersArrayTag>(field);
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
      FUZZTEST_INTERNAL_CHECK(false, "Unsupported base type");
  }
}

// Flatbuffers enum domain implementation.
template <typename Underlaying>
class FlatbuffersEnumDomainImpl
    // Value type: Underlaying
    // Corpus type: ElementOfImplCorpusType
    // See ElementOfImpl for more details.
    : public ElementOfImpl<Underlaying> {
 public:
  using typename ElementOfImpl<Underlaying>::DomainBase::corpus_type;
  using typename ElementOfImpl<Underlaying>::DomainBase::value_type;

  explicit FlatbuffersEnumDomainImpl(const reflection::Enum* enum_def)
      : ElementOfImpl<Underlaying>(GetEnumValues(enum_def)),
        enum_def_(enum_def) {}

  auto GetPrinter() const { return Printer{*this}; }

 private:
  const reflection::Enum* enum_def_;

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

// From flatbuffers documentation:
// Unions are encoded as the combination of two fields: an enum representing the
// union choice and the offset to the actual element.
// The type of the enum is always uint8_t as generated by the flatbuffers
// compiler.
using FlatbuffersUnionTypeDomainImpl = FlatbuffersEnumDomainImpl<uint8_t>;

// Domain implementation for flatbuffers struct types.
// The corpus type is a map of field ids to field values.
class FlatbuffersStructUntypedDomainImpl
    : public domain_implementor::DomainBase<
          // Derived, for CRTP needs. See DomainBase for more details.
          FlatbuffersStructUntypedDomainImpl,
          // ValueType - user facing type
          const flatbuffers::Struct* absl_nonnull,
          // CorpusType - internal representation of ValueType,
          // a map of field ids to field values.
          absl::flat_hash_map<
              // a.k.a. uint16_t
              decltype(static_cast<reflection::Field*>(nullptr)->id()),
              // Fancy wrapper around `void*`: knows about the exact type of
              // stored value and can copy it using exact type copy constructor
              // via `CopyFrom` method.
              GenericDomainCorpusType>> {
 public:
  using typename FlatbuffersStructUntypedDomainImpl::DomainBase::corpus_type;
  using typename FlatbuffersStructUntypedDomainImpl::DomainBase::value_type;

  FlatbuffersStructUntypedDomainImpl(const reflection::Schema* schema,
                                     const reflection::Object* struct_object)
      : schema_(schema), struct_object_(struct_object) {}

  FlatbuffersStructUntypedDomainImpl(
      const FlatbuffersStructUntypedDomainImpl& other)
      : schema_(other.schema_), struct_object_(other.struct_object_) {
    absl::MutexLock l(&other.mutex_);
    domains_ = other.domains_;
  }

  FlatbuffersStructUntypedDomainImpl& operator=(
      const FlatbuffersStructUntypedDomainImpl& other) {
    schema_ = other.schema_;
    struct_object_ = other.struct_object_;
    absl::MutexLock l(&other.mutex_);
    domains_ = other.domains_;
    return *this;
  }

  FlatbuffersStructUntypedDomainImpl(FlatbuffersStructUntypedDomainImpl&& other)
      : schema_(other.schema_), struct_object_(other.struct_object_) {
    absl::MutexLock l(&other.mutex_);
    domains_ = std::move(other.domains_);
  }

  FlatbuffersStructUntypedDomainImpl& operator=(
      FlatbuffersStructUntypedDomainImpl&& other) {
    schema_ = other.schema_;
    struct_object_ = other.struct_object_;
    absl::MutexLock l(&other.mutex_);
    domains_ = std::move(other.domains_);
    return *this;
  }

  // Returns the domain for the given field.
  // The domain is cached, and the same instance is returned for the same
  // field.
  template <typename T>
  auto& GetSubDomain(const reflection::Field* absl_nonnull field) const {
    using DomainT = decltype(GetDomainForField<T>(field));
    // Do the operation under a lock to prevent race conditions in `const`
    // methods.
    absl::MutexLock l(&mutex_);
    auto it = domains_.find(field->id());
    if (it == domains_.end()) {
      it = domains_
               .try_emplace(field->id(), std::in_place_type<DomainT>,
                            GetDomainForField<T>(field))
               .first;
    }
    return it->second.template GetAs<DomainT>();
  }

  // Initializes the corpus value.
  corpus_type Init(absl::BitGenRef prng);

  // Mutates the corpus value.
  void Mutate(corpus_type& val, absl::BitGenRef prng,
              const domain_implementor::MutationMetadata& metadata,
              bool only_shrink);

  // Counts the number of fields that can be mutated.
  // Returns the number of fields in the flattened tree for supported field
  // types.
  uint64_t CountNumberOfFields(corpus_type& val);

  // Mutates the selected field.
  // The selected field index is based on the flattened tree.
  uint64_t MutateSelectedField(
      corpus_type& val, absl::BitGenRef prng,
      const domain_implementor::MutationMetadata& metadata, bool only_shrink,
      uint64_t selected_field_index);

  auto GetPrinter() const { return Printer{*this}; }

  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const;

  value_type GetValue(const corpus_type& value) const {
    // Untyped domain does not support GetValue since if it is a nested table
    // it would need the top level table corpus value to be able to build it.
    return nullptr;
  }

  // Converts the struct pointer to a corpus value.
  std::optional<corpus_type> FromValue(const value_type& value) const;

  // Builds the struct in a builder.
  std::optional<flatbuffers::uoffset_t> BuildValue(
      const corpus_type& value, flatbuffers::FlatBufferBuilder& builder) const;

  // Builds the struct in a buffer.
  void BuildValue(const corpus_type& value, uint8_t* buf) const;

  // Converts the IRObject to a corpus value.
  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const;

  // Converts the corpus value to an IRObject.
  IRObject SerializeCorpus(const corpus_type& value) const;

 private:
  const reflection::Schema* schema_;
  const reflection::Object* struct_object_;
  mutable absl::Mutex mutex_;
  mutable absl::flat_hash_map<
      // a.k.a. uint16_t
      decltype(static_cast<reflection::Field*>(nullptr)->id()),
      // Fancy wrapper around `void*`: knows about the exact type of
      // stored value and can copy it using exact type copy constructor
      // via `CopyFrom` method.
      GenericDomainCorpusType>
      domains_ ABSL_GUARDED_BY(mutex_);

  const reflection::Field* absl_nullable GetFieldById(
      typename corpus_type::key_type id) const {
    const auto it =
        absl::c_find_if(*struct_object_->fields(),
                        [id](const auto* field) { return field->id() == id; });
    return it != struct_object_->fields()->end() ? *it : nullptr;
  }

  // Returns the domain for the given field.
  template <typename T>
  auto GetDomainForField(const reflection::Field* absl_nonnull field) const {
    if constexpr (std::is_same_v<T, FlatbuffersArrayTag>) {
      // TODO(b/405938558): Implement this.
      return Domain<bool>{Arbitrary<bool>()};
    } else if constexpr (is_flatbuffers_enum_tag_v<T>) {
      auto enum_object = schema_->enums()->Get(field->type()->index());
      return Domain<typename T::type>{
          FlatbuffersEnumDomainImpl<typename T::type>(enum_object)};
    } else if constexpr (std::is_same_v<T, FlatbuffersStructTag>) {
      const reflection::Object* sub_object =
          schema_->objects()->Get(field->type()->index());
      FUZZTEST_INTERNAL_CHECK(sub_object->is_struct(),
                              "Field must be a struct type.");
      return Domain<const flatbuffers::Struct*>(
          FlatbuffersStructUntypedDomainImpl{schema_, sub_object});
    } else if constexpr (std::is_integral_v<T> || std::is_floating_point_v<T>) {
      return Domain<T>{Arbitrary<T>()};
    } else {
      FUZZTEST_INTERNAL_CHECK(false, "Unsupported type");
      // Return a no-op domain for the static checks to pass.
      return Domain<bool>{Arbitrary<bool>()};
    }
  }

  struct InitializeVisitor {
    FlatbuffersStructUntypedDomainImpl& self;
    absl::BitGenRef prng;
    corpus_type& val;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = self.GetSubDomain<T>(field);
      val[field->id()] = domain.Init(prng);
    }
  };

  struct CountNumberOfFieldsVisitor {
    const FlatbuffersStructUntypedDomainImpl& self;
    uint64_t& total_weight;
    corpus_type& corpus;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) const {
      if constexpr (std::is_same_v<T, FlatbuffersArrayTag>) {
        // TODO(b/405938558): Implement this.
        return;
      } else if constexpr (std::is_same_v<T, FlatbuffersStructTag>) {
        auto sub_object = self.schema_->objects()->Get(field->type()->index());
        FUZZTEST_INTERNAL_CHECK(sub_object->is_struct(),
                                "Field must be a struct type.");
        auto sub_domain = self.GetSubDomain<T>(field);
        total_weight += sub_domain.CountNumberOfFields(corpus.at(field->id()));
      } else {
        total_weight++;
      }
    }
  };

  struct MutateVisitor {
    FlatbuffersStructUntypedDomainImpl& self;
    absl::BitGenRef prng;
    const domain_implementor::MutationMetadata& metadata;
    bool only_shrink;
    corpus_type& val;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = self.GetSubDomain<T>(field);
      if (auto it = val.find(field->id()); it != val.end()) {
        domain.Mutate(it->second, prng, metadata, only_shrink);
      } else if (!only_shrink) {
        val[field->id()] = domain.Init(prng);
      }
    }
  };

  struct ParseVisitor {
    const FlatbuffersStructUntypedDomainImpl& self;
    const IRObject& obj;
    std::optional<GenericDomainCorpusType>& out;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      out = self.GetSubDomain<T>(field).ParseCorpus(obj);
    }
  };

  struct SerializeVisitor {
    const FlatbuffersStructUntypedDomainImpl& self;
    const GenericDomainCorpusType& corpus_value;
    IRObject& out;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      out = self.GetSubDomain<T>(field).SerializeCorpus(corpus_value);
    }
  };

  struct Printer {
    const FlatbuffersStructUntypedDomainImpl& self;

    void PrintCorpusValue(const corpus_type& value,
                          domain_implementor::RawSink out,
                          domain_implementor::PrintMode mode) const {
      absl::Format(out, "{");
      bool first = true;
      for (const auto& [id, field_corpus] : value) {
        if (!first) {
          absl::Format(out, ", ");
        }
        const reflection::Field* absl_nullable field = self.GetFieldById(id);
        if (field == nullptr) {
          absl::Format(out, "<unknown field: %d>", id);
        } else {
          VisitFlatbufferField(self.schema_, field,
                               PrinterVisitor{self, field_corpus, out, mode});
        }
        first = false;
      }
      absl::Format(out, "}");
    }
  };

  struct PrinterVisitor {
    const FlatbuffersStructUntypedDomainImpl& self;
    const GenericDomainCorpusType& val;
    domain_implementor::RawSink out;
    domain_implementor::PrintMode mode;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) const {
      auto& domain = self.GetSubDomain<T>(field);
      absl::Format(out, "%s: ", field->name()->str());
      domain_implementor::PrintValue(domain, val, out, mode);
    }
  };

  struct ValidateVisitor {
    const FlatbuffersStructUntypedDomainImpl& self;
    const GenericDomainCorpusType& corpus_value;
    absl::Status& out;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = self.GetSubDomain<T>(field);
      out = domain.ValidateCorpusValue(corpus_value);
      if (!out.ok()) {
        out = Prefix(out, absl::StrCat("Invalid value for field ",
                                       field->name()->str()));
      }
    }
  };

  struct FromValueVisitor {
    const FlatbuffersStructUntypedDomainImpl& self;
    value_type value;
    corpus_type& out;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) const {
      [[maybe_unused]]
      reflection::BaseType base_type = field->type()->base_type();
      auto& domain = self.GetSubDomain<T>(field);
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
      auto& domain = self.GetSubDomain<T>(field);
      if constexpr (is_flatbuffers_enum_tag_v<T> || std::is_integral_v<T> ||
                    std::is_floating_point_v<T>) {
        FUZZTEST_INTERNAL_CHECK(flatbuffers::IsScalar(base_type),
                                "Field must be an scalar type.");
        auto inner_value = domain.GetValue(corpus_value.at(field->id()));
        flatbuffers::WriteScalar(struct_ptr + field->offset(), inner_value);
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
      } else if constexpr (std::is_same_v<T, FlatbuffersArrayTag>) {
        // TODO (b/405938558): Implement array support.
      }
    }
  };
};

class FlatbuffersTableUntypedDomainImpl;

// Flatbuffers union domain implementation.
class FlatbuffersUnionDomainImpl
    : public domain_implementor::DomainBase<
          // Derived, for CRTP needs. See DomainBase for more details.
          FlatbuffersUnionDomainImpl,
          // ValueType - user facing type
          std::pair<typename FlatbuffersUnionTypeDomainImpl::value_type,
                    const void*>,
          // CorpusType - internal representation of ValueType
          std::pair<
              // `Union choice` type representation
              typename FlatbuffersUnionTypeDomainImpl::corpus_type,
              // Fancy wrapper around `void*`: knows about the exact type
              // of stored value and can copy it using exact type copy
              // constructor via `AnyBase::CopyFrom` method.
              GenericDomainCorpusType>> {
 public:
  using typename FlatbuffersUnionDomainImpl::DomainBase::corpus_type;
  using typename FlatbuffersUnionDomainImpl::DomainBase::value_type;

  FlatbuffersUnionDomainImpl(const reflection::Schema* schema,
                             const reflection::Enum* union_def)
      : schema_(schema), union_def_(union_def), type_domain_(union_def) {}

  FlatbuffersUnionDomainImpl(const FlatbuffersUnionDomainImpl& other)
      : schema_(other.schema_),
        union_def_(other.union_def_),
        type_domain_(other.type_domain_) {
    absl::MutexLock l(&other.mutex_);
    domains_ = other.domains_;
  }

  FlatbuffersUnionDomainImpl(FlatbuffersUnionDomainImpl&& other)
      : schema_(other.schema_),
        union_def_(other.union_def_),
        type_domain_(std::move(other.type_domain_)) {
    absl::MutexLock l(&other.mutex_);
    domains_ = std::move(other.domains_);
  }

  FlatbuffersUnionDomainImpl& operator=(
      const FlatbuffersUnionDomainImpl& other) {
    schema_ = other.schema_;
    union_def_ = other.union_def_;
    type_domain_ = other.type_domain_;
    absl::MutexLock l(&other.mutex_);
    domains_ = other.domains_;
    return *this;
  }

  FlatbuffersUnionDomainImpl& operator=(FlatbuffersUnionDomainImpl&& other) {
    schema_ = other.schema_;
    union_def_ = other.union_def_;
    type_domain_ = std::move(other.type_domain_);
    absl::MutexLock l(&other.mutex_);
    domains_ = std::move(other.domains_);
    return *this;
  }

  // Initializes the corpus value.
  corpus_type Init(absl::BitGenRef prng);

  // Mutates the corpus value.
  void Mutate(corpus_type& val, absl::BitGenRef prng,
              const domain_implementor::MutationMetadata& metadata,
              bool only_shrink);

  uint64_t CountNumberOfFields(corpus_type& val);

  auto GetPrinter() const { return Printer{*this}; }

  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const;

  // UNSUPPORTED: Flatbuffers unions user values are not supported.
  value_type GetValue(const corpus_type& value) const {
    FUZZTEST_INTERNAL_CHECK(false, "GetValue is not supported for unions.");
  }

  // Gets the type of the union field.
  auto GetType(const corpus_type& value) const {
    return type_domain_.GetValue(value.first);
  }

  // Creates flatbuffer from the corpus value.
  std::optional<flatbuffers::uoffset_t> BuildValue(
      const corpus_type& value, flatbuffers::FlatBufferBuilder& builder) const;

  // Converts the value to a corpus value.
  std::optional<corpus_type> FromValue(const value_type& value) const;

  // Converts the IRObject to a corpus value.
  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const;

  // Converts the corpus value to an IRObject.
  IRObject SerializeCorpus(const corpus_type& value) const;

  // Returns the domain for the given enum value.
  template <typename T>
  auto& GetSubDomain(const reflection::EnumVal& enum_value) const {
    using DomainT = decltype(GetDomainForType<T>(enum_value));
    absl::MutexLock l(&mutex_);
    auto it = domains_.find(enum_value.value());
    if (it == domains_.end()) {
      it = domains_
               .try_emplace(enum_value.value(), std::in_place_type<DomainT>,
                            GetDomainForType<T>(enum_value))
               .first;
    }
    return it->second.GetAs<DomainT>();
  }

 private:
  const reflection::Schema* schema_;
  const reflection::Enum* union_def_;
  FlatbuffersEnumDomainImpl<typename value_type::first_type> type_domain_;
  mutable absl::Mutex mutex_;
  mutable absl::flat_hash_map<typename value_type::first_type, CopyableAny>
      domains_ ABSL_GUARDED_BY(mutex_);

  // Creates new or returns existing domain for the given enum value.
  template <typename T>
  auto GetDomainForType(const reflection::EnumVal& enum_value) const;

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
    : public domain_implementor::DomainBase<
          // Derived, for CRTP needs. See DomainBase for more details.
          FlatbuffersTableUntypedDomainImpl,
          // ValueType - user facing type
          const flatbuffers::Table* absl_nonnull,
          // CorpusType - internal representation of ValueType,
          // a map of field ids to field values.
          absl::flat_hash_map<
              // a.k.a. uint16_t
              decltype(static_cast<reflection::Field*>(nullptr)->id()),
              // Fancy wrapper around `void*`: knows about the exact type of
              // stored value and can copy it using exact type copy constructor
              // via `CopyFrom` method.
              GenericDomainCorpusType>> {
 public:
  using typename FlatbuffersTableUntypedDomainImpl::DomainBase::corpus_type;
  using typename FlatbuffersTableUntypedDomainImpl::DomainBase::value_type;

  explicit FlatbuffersTableUntypedDomainImpl(
      const reflection::Schema* schema, const reflection::Object* table_object)
      : schema_(schema), table_object_(table_object) {}

  FlatbuffersTableUntypedDomainImpl(
      const FlatbuffersTableUntypedDomainImpl& other)
      : schema_(other.schema_), table_object_(other.table_object_) {
    absl::MutexLock l_other(&other.mutex_);
    absl::MutexLock l_this(&mutex_);
    domains_ = other.domains_;
  }

  FlatbuffersTableUntypedDomainImpl& operator=(
      const FlatbuffersTableUntypedDomainImpl& other) {
    schema_ = other.schema_;
    table_object_ = other.table_object_;
    absl::MutexLock l_other(&other.mutex_);
    absl::MutexLock l_this(&mutex_);
    domains_ = other.domains_;
    return *this;
  }

  FlatbuffersTableUntypedDomainImpl(FlatbuffersTableUntypedDomainImpl&& other)
      : schema_(other.schema_), table_object_(other.table_object_) {
    absl::MutexLock l_other(&other.mutex_);
    absl::MutexLock l_this(&mutex_);
    domains_ = std::move(other.domains_);
  }

  FlatbuffersTableUntypedDomainImpl& operator=(
      FlatbuffersTableUntypedDomainImpl&& other) {
    schema_ = other.schema_;
    table_object_ = other.table_object_;
    absl::MutexLock l_other(&other.mutex_);
    absl::MutexLock l_this(&mutex_);
    domains_ = std::move(other.domains_);
    return *this;
  }

  // Initializes the corpus value.
  corpus_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) {
      return *seed;
    }
    corpus_type val;
    for (const auto* field : *table_object_->fields()) {
      VisitFlatbufferField(schema_, field, InitializeVisitor{*this, prng, val});
    }
    return val;
  }

  // Mutates the corpus value.
  void Mutate(corpus_type& val, absl::BitGenRef prng,
              const domain_implementor::MutationMetadata& metadata,
              bool only_shrink) {
    auto total_weight = CountNumberOfFields(val);
    auto selected_weight =
        absl::Uniform(absl::IntervalClosedClosed, prng, 0ul, total_weight - 1);

    MutateSelectedField(val, prng, metadata, only_shrink, selected_weight);
  }

  // Returns the domain for the given vector field.
  template <typename Element>
  auto GetDomainForVectorField(const reflection::Field* field) const {
    if constexpr (is_flatbuffers_enum_tag_v<Element>) {
      auto enum_object = schema_->enums()->Get(field->type()->index());
      auto inner = OptionalOf(
          VectorOf(
              FlatbuffersEnumDomainImpl<typename Element::type>(enum_object))
              .WithMaxSize(std::numeric_limits<flatbuffers::uoffset_t>::max()));
      if (!field->optional()) {
        inner.SetWithoutNull();
      }
      return Domain<value_type_t<decltype(inner)>>{inner};
    } else if constexpr (std::is_same_v<Element, FlatbuffersTableTag>) {
      auto table_object = schema_->objects()->Get(field->type()->index());
      auto inner = OptionalOf(
          VectorOf(FlatbuffersTableUntypedDomainImpl{schema_, table_object})
              .WithMaxSize(std::numeric_limits<flatbuffers::uoffset_t>::max()));
      if (!field->optional()) {
        inner.SetWithoutNull();
      }
      return Domain<std::optional<std::vector<const flatbuffers::Table*>>>{
          inner};
    } else if constexpr (std::is_same_v<Element, FlatbuffersStructTag>) {
      auto struct_object = schema_->objects()->Get(field->type()->index());
      auto inner = OptionalOf(
          VectorOf(FlatbuffersStructUntypedDomainImpl{schema_, struct_object})
              .WithMaxSize(std::numeric_limits<flatbuffers::uoffset_t>::max()));
      if (!field->optional()) {
        inner.SetWithoutNull();
      }
      return Domain<std::optional<std::vector<const flatbuffers::Struct*>>>{
          inner};
    } else if constexpr (std::is_same_v<Element, FlatbuffersUnionTag>) {
      auto union_type = schema_->enums()->Get(field->type()->index());
      auto inner = OptionalOf(
          VectorOf(FlatbuffersUnionDomainImpl{schema_, union_type})
              .WithMaxSize(std::numeric_limits<flatbuffers::uoffset_t>::max()));
      if (!field->optional()) {
        inner.SetWithoutNull();
      }
      return Domain<value_type_t<decltype(inner)>>{inner};
    } else {
      auto inner = OptionalOf(
          VectorOf(ArbitraryImpl<Element>())
              .WithMaxSize(std::numeric_limits<flatbuffers::uoffset_t>::max()));
      if (!field->optional()) {
        inner.SetWithoutNull();
      }
      return Domain<std::optional<std::vector<Element>>>{inner};
    }
  }

  // Returns the domain for the given field.
  template <typename T>
  auto GetDomainForField(const reflection::Field* field) const {
    if constexpr (std::is_same_v<T, FlatbuffersArrayTag>) {
      FUZZTEST_INTERNAL_CHECK(
          false, "Arrays in tables are not supported in flatbuffers.");
      // Return a placeholder domain to make the compiler happy.
      return Domain<std::optional<bool>>{Arbitrary<std::optional<bool>>()};
    } else if constexpr (is_flatbuffers_enum_tag_v<T>) {
      auto enum_object = schema_->enums()->Get(field->type()->index());
      auto domain =
          OptionalOf(FlatbuffersEnumDomainImpl<typename T::type>(enum_object));
      if (!field->optional()) {
        domain.SetWithoutNull();
      }
      return Domain<value_type_t<decltype(domain)>>{domain};
    } else if constexpr (std::is_same_v<T, FlatbuffersTableTag>) {
      auto table_object = schema_->objects()->Get(field->type()->index());
      auto inner =
          OptionalOf(FlatbuffersTableUntypedDomainImpl{schema_, table_object});
      if (!field->optional()) {
        inner.SetWithoutNull();
      }
      return Domain<std::optional<const flatbuffers::Table*>>{inner};
    } else if constexpr (std::is_same_v<T, FlatbuffersStructTag>) {
      auto struct_object = schema_->objects()->Get(field->type()->index());
      auto inner = OptionalOf(
          FlatbuffersStructUntypedDomainImpl{schema_, struct_object});
      if (!field->optional()) {
        inner.SetWithoutNull();
      }
      return Domain<std::optional<const flatbuffers::Struct*>>(inner);
    } else if constexpr (std::is_same_v<T, FlatbuffersUnionTag>) {
      auto union_type = schema_->enums()->Get(field->type()->index());
      auto inner = OptionalOf(FlatbuffersUnionDomainImpl{schema_, union_type});
      return Domain<value_type_t<decltype(inner)>>{inner};
    } else if constexpr (is_flatbuffers_vector_tag_v<T>) {
      return GetDomainForVectorField<typename T::value_type>(field);
    } else {
      auto inner = OptionalOf(ArbitraryImpl<T>());
      if (!field->optional()) {
        inner.SetWithoutNull();
      }
      return Domain<std::optional<T>>{inner};
    }
  }

  // Returns the domain for the given field.
  // The domain is cached, and the same instance is returned for the same
  // field.
  template <typename T>
  auto& GetSubDomain(const reflection::Field* absl_nonnull field) const {
    using DomainT = decltype(GetDomainForField<T>(field));
    // Do the operation under a lock to prevent race conditions in `const`
    // methods.
    absl::MutexLock l(&mutex_);
    auto it = domains_.find(field->id());
    if (it == domains_.end()) {
      it = domains_
               .try_emplace(field->id(), std::in_place_type<DomainT>,
                            GetDomainForField<T>(field))
               .first;
    }
    return it->second.template GetAs<DomainT>();
  }

  // Counts the number of fields that can be mutated.
  // Returns the number of fields in the flattened tree for supported field
  // types.
  uint64_t CountNumberOfFields(corpus_type& val) {
    uint64_t total_weight = 0;
    for (const auto* field : *table_object_->fields()) {
      VisitFlatbufferField(
          schema_, field, CountNumberOfFieldsVisitor{*this, total_weight, val});
    }
    return total_weight;
  }

  // Mutates the selected field.
  // The selected field index is based on the flattened tree.
  uint64_t MutateSelectedField(
      corpus_type& val, absl::BitGenRef prng,
      const domain_implementor::MutationMetadata& metadata, bool only_shrink,
      uint64_t selected_field_index) {
    uint64_t field_counter = 0;
    for (const auto* field : *table_object_->fields()) {
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
        } else {
          field_counter +=
              GetSubDomain<FlatbuffersTableTag>(field).MutateSelectedField(
                  val[field->id()], prng, metadata, only_shrink,
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
                GetSubDomain<FlatbuffersVectorTag<FlatbuffersTableTag>>(field)
                    .MutateSelectedField(val[field->id()], prng, metadata,
                                         only_shrink,
                                         selected_field_index - field_counter);
          } else {
            field_counter +=
                GetSubDomain<FlatbuffersVectorTag<FlatbuffersStructTag>>(field)
                    .MutateSelectedField(val[field->id()], prng, metadata,
                                         only_shrink,
                                         selected_field_index - field_counter);
          }
        } else if (elem_type == reflection::BaseType::Union) {
          field_counter +=
              GetSubDomain<FlatbuffersVectorTag<FlatbuffersUnionTag>>(field)
                  .MutateSelectedField(val[field->id()], prng, metadata,
                                       only_shrink,
                                       selected_field_index - field_counter);
        }
      }

      if (base_type == reflection::BaseType::Union) {
        field_counter +=
            GetSubDomain<FlatbuffersUnionTag>(field).MutateSelectedField(
                val[field->id()], prng, metadata, only_shrink,
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
      if (field == nullptr) continue;
      absl::Status result;
      VisitFlatbufferField(schema_, field,
                           ValidateVisitor{*this, field_corpus, result});
      if (!result.ok()) return result;
    }
    return absl::OkStatus();
  }

  value_type GetValue(const corpus_type& value) const {
    // Untyped domain does not support GetValue since if it is a nested table
    // it would need the top level table corpus value to be able to build it.
    return nullptr;
  }

  // Converts the table pointer to a corpus value.
  std::optional<corpus_type> FromValue(const value_type& value) const {
    if (value == nullptr) {
      return std::nullopt;
    }
    corpus_type ret;
    for (const auto* field : *table_object_->fields()) {
      VisitFlatbufferField(schema_, field, FromValueVisitor{*this, value, ret});
    }
    return ret;
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

  uint32_t BuildTable(const corpus_type& value,
                      flatbuffers::FlatBufferBuilder& builder) const {
    // Add all the fields to the builder.

    // Offsets is the map of field id to its offset in the table.
    absl::flat_hash_map<typename corpus_type::key_type, flatbuffers::uoffset_t>
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

 private:
  const reflection::Schema* absl_nonnull schema_;
  const reflection::Object* absl_nonnull table_object_;
  mutable absl::Mutex mutex_;
  mutable absl::flat_hash_map<typename corpus_type::key_type, CopyableAny>
      domains_ ABSL_GUARDED_BY(mutex_);

  const reflection::Field* absl_nullable GetFieldById(
      typename corpus_type::key_type id) const {
    const auto it =
        absl::c_find_if(*table_object_->fields(),
                        [id](const auto* field) { return field->id() == id; });
    return it != table_object_->fields()->end() ? *it : nullptr;
  }

  struct SerializeVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    const GenericDomainCorpusType& corpus_value;
    IRObject& out;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      out = self.GetSubDomain<T>(field).SerializeCorpus(corpus_value);
    }
  };

  struct FromValueVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    value_type value;
    corpus_type& out;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) const {
      [[maybe_unused]]
      reflection::BaseType base_type = field->type()->base_type();
      auto& domain = self.GetSubDomain<T>(field);
      value_type_t<std::decay_t<decltype(domain)>> inner_value;

      if constexpr (is_flatbuffers_enum_tag_v<T>) {
        FUZZTEST_INTERNAL_CHECK(base_type >= reflection::BaseType::Byte &&
                                    base_type <= reflection::BaseType::ULong,
                                "Field must be an enum type.");
        if (field->optional() && !value->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::make_optional(value->GetField<typename T::type>(
              field->offset(), field->default_integer()));
        }
      } else if constexpr (std::is_integral_v<T>) {
        FUZZTEST_INTERNAL_CHECK(base_type >= reflection::BaseType::Bool &&
                                    base_type <= reflection::BaseType::ULong,
                                "Field must be an integer type.");
        if (field->optional() && !value->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::make_optional(
              value->GetField<T>(field->offset(), field->default_integer()));
        }
      } else if constexpr (std::is_floating_point_v<T>) {
        FUZZTEST_INTERNAL_CHECK(base_type >= reflection::BaseType::Float &&
                                    base_type <= reflection::BaseType::Double,
                                "Field must be a floating point type.");
        if (field->optional() && !value->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::make_optional(
              value->GetField<T>(field->offset(), field->default_real()));
        }
      } else if constexpr (std::is_same_v<T, std::string>) {
        FUZZTEST_INTERNAL_CHECK(base_type == reflection::BaseType::String,
                                "Field must be a string type.");
        if (!value->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::make_optional(
              value->GetPointer<flatbuffers::String*>(field->offset())->str());
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersTableTag>) {
        auto sub_object = self.schema_->objects()->Get(field->type()->index());
        FUZZTEST_INTERNAL_CHECK(
            base_type == reflection::BaseType::Obj && !sub_object->is_struct(),
            "Field must be a table type.");
        inner_value =
            value->GetPointer<const flatbuffers::Table*>(field->offset());
      } else if constexpr (std::is_same_v<T, FlatbuffersStructTag>) {
        auto sub_object = self.schema_->objects()->Get(field->type()->index());
        FUZZTEST_INTERNAL_CHECK(
            base_type == reflection::BaseType::Obj && sub_object->is_struct(),
            "Field must be a struct type.");
        inner_value =
            value->GetStruct<const flatbuffers::Struct*>(field->offset());
      } else if constexpr (is_flatbuffers_vector_tag_v<T>) {
        FUZZTEST_INTERNAL_CHECK(base_type == reflection::BaseType::Vector ||
                                    base_type == reflection::BaseType::Vector64,
                                "Field must be a vector type.");
        if (!value->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          VisitVector<typename T::value_type, std::decay_t<decltype(domain)>>(
              field, inner_value);
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersUnionTag>) {
        constexpr char kUnionTypeFieldSuffix[] = "_type";
        auto enumdef = self.schema_->enums()->Get(field->type()->index());
        auto type_field = self.table_object_->fields()->LookupByKey(
            (field->name()->str() + kUnionTypeFieldSuffix).c_str());
        if (type_field == nullptr) {
          return;
        }
        auto union_type = value->GetField<uint8_t>(type_field->offset(), 0);
        if (union_type > 0 /* NONE */) {
          auto enumval = enumdef->values()->LookupByKey(union_type);
          auto union_object =
              self.schema_->objects()->Get(enumval->union_type()->index());
          if (union_object->is_struct()) {
            auto union_value = value->template GetPointer<flatbuffers::Struct*>(
                field->offset());
            inner_value = std::make_pair(union_type, union_value);
          } else {
            auto union_value =
                value->GetPointer<flatbuffers::Table*>(field->offset());
            inner_value = std::make_pair(union_type, union_value);
          }
        }
      }

      auto inner = domain.FromValue(inner_value);
      if (inner) {
        out[field->id()] = std::move(inner.value());
      }
    };

    template <typename ElementType, typename Domain>
    void VisitVector(const reflection::Field* field,
                     value_type_t<Domain>& inner_value) const {
      if constexpr (std::is_integral_v<ElementType> ||
                    std::is_floating_point_v<ElementType>) {
        auto vec = value->GetPointer<flatbuffers::Vector<ElementType>*>(
            field->offset());
        inner_value = std::make_optional(std::vector<ElementType>());
        inner_value->reserve(vec->size());
        for (auto i = 0; i < vec->size(); ++i) {
          inner_value->push_back(vec->Get(i));
        }
      } else if constexpr (is_flatbuffers_enum_tag_v<ElementType>) {
        using Underlaying = typename ElementType::type;
        auto vec = value->GetPointer<flatbuffers::Vector<Underlaying>*>(
            field->offset());
        inner_value = std::make_optional(std::vector<Underlaying>());
        inner_value->reserve(vec->size());
        for (auto i = 0; i < vec->size(); ++i) {
          inner_value->push_back(vec->Get(i));
        }
      } else if constexpr (std::is_same_v<ElementType, std::string>) {
        auto vec = value->GetPointer<
            flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>>*>(
            field->offset());
        inner_value = std::make_optional(std::vector<std::string>());
        inner_value->reserve(vec->size());
        for (auto i = 0; i < vec->size(); ++i) {
          inner_value->push_back(vec->Get(i)->str());
        }
      } else if constexpr (std::is_same_v<ElementType, FlatbuffersTableTag>) {
        auto vec = value->GetPointer<
            flatbuffers::Vector<flatbuffers::Offset<flatbuffers::Table>>*>(
            field->offset());
        inner_value =
            std::make_optional(std::vector<const flatbuffers::Table*>());
        inner_value->reserve(vec->size());
        for (auto i = 0; i < vec->size(); ++i) {
          inner_value->push_back(vec->Get(i));
        }
      } else if constexpr (std::is_same_v<ElementType, FlatbuffersStructTag>) {
        const reflection::Object* struct_object =
            self.schema_->objects()->Get(field->type()->index());
        auto vec =
            value->template GetPointer<const flatbuffers::Vector<uint8_t>*>(
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
        auto type_field = self.table_object_->fields()->LookupByKey(
            (field->name()->str() + kUnionTypeFieldSuffix).c_str());
        if (type_field == nullptr) {
          return;
        }
        auto type_vec = value->GetPointer<flatbuffers::Vector<uint8_t>*>(
            type_field->offset());
        auto value_vec =
            value->GetPointer<flatbuffers::Vector<flatbuffers::Offset<void>>*>(
                field->offset());
        inner_value = std::make_optional(
            typename std::decay_t<decltype(inner_value)>::value_type{});
        inner_value->reserve(value_vec->size());
        for (auto i = 0; i < value_vec->size(); ++i) {
          inner_value->push_back(
              std::make_pair(type_vec->Get(i), value_vec->Get(i)));
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
    const typename corpus_type::value_type::second_type& corpus_value;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      if constexpr (std::is_same_v<T, std::string>) {
        auto& domain = self.GetSubDomain<T>(field);
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
        VisitVector<typename T::value_type>(field, self.GetSubDomain<T>(field));
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
      const reflection::Field* type_field =
          self.table_object_->fields()->LookupByKey(
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
          std::decay_t<decltype(inner_domain)>>::first_type>
          vec_types;
      vec_types.reserve(container_corpus.size());
      vec_types.reserve(container_corpus.size());
      std::vector<flatbuffers::Offset<flatbuffers::Table>> vec_offsets;
      vec_offsets.reserve(container_corpus.size());
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
      auto size = flatbuffers::GetTypeSize(field->type()->base_type());
      if constexpr (std::is_integral_v<T> || std::is_floating_point_v<T> ||
                    is_flatbuffers_enum_tag_v<T>) {
        auto& domain = self.GetSubDomain<T>(field);
        auto v = domain.GetValue(corpus_value);
        if (!v) {
          return;
        }
        // Store "inline field" value inline.
        builder.Align(size);
        builder.PushBytes(reinterpret_cast<const uint8_t*>(&v), size);
        builder.TrackField(field->offset(), builder.GetSize());
      } else if constexpr (std::is_same_v<T, std::string> ||
                           is_flatbuffers_vector_tag_v<T>) {
        // "Out-of-line field". Store just offset.
        if constexpr (is_flatbuffers_vector_tag_v<T>) {
          if constexpr (std::is_same_v<typename T::value_type,
                                       FlatbuffersUnionTag>) {
            constexpr char kUnionTypeFieldSuffix[] = "_type";
            const reflection::Field* type_field =
                self.table_object_->fields()->LookupByKey(
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
              self.table_object_->fields()->LookupByKey(
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

  struct ParseVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    const IRObject& obj;
    std::optional<GenericDomainCorpusType>& out;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      out = self.GetSubDomain<T>(field).ParseCorpus(obj);
    }
  };

  struct ValidateVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    const GenericDomainCorpusType& corpus_value;
    absl::Status& out;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = self.GetSubDomain<T>(field);
      out = domain.ValidateCorpusValue(corpus_value);
      if (!out.ok()) {
        out = Prefix(out, absl::StrCat("Invalid value for field ",
                                       field->name()->str()));
      }
    }
  };

  struct InitializeVisitor {
    FlatbuffersTableUntypedDomainImpl& self;
    absl::BitGenRef prng;
    corpus_type& val;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = self.GetSubDomain<T>(field);
      val[field->id()] = domain.Init(prng);
    }
  };

  struct CountNumberOfFieldsVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    uint64_t& total_weight;
    corpus_type& corpus;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) const {
      // Add the weight of the field itself.
      total_weight += 1;

      auto domain = self.GetSubDomain<T>(field);
      if (auto it = corpus.find(field->id()); it != corpus.end()) {
        // Add the weight of the field corpus.
        total_weight += domain.CountNumberOfFields(it->second);
      }
    }
  };

  struct MutateVisitor {
    FlatbuffersTableUntypedDomainImpl& self;
    absl::BitGenRef prng;
    const domain_implementor::MutationMetadata& metadata;
    bool only_shrink;
    corpus_type& val;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) {
      auto& domain = self.GetSubDomain<T>(field);
      if (auto it = val.find(field->id()); it != val.end()) {
        domain.Mutate(it->second, prng, metadata, only_shrink);
      } else if (!only_shrink) {
        val[field->id()] = domain.Init(prng);
      }
    }
  };

  struct Printer {
    const FlatbuffersTableUntypedDomainImpl& self;

    void PrintCorpusValue(const corpus_type& value,
                          domain_implementor::RawSink out,
                          domain_implementor::PrintMode mode) const {
      absl::Format(out, "{");
      bool first = true;
      for (const auto& [id, field_corpus] : value) {
        if (!first) {
          absl::Format(out, ", ");
        }
        const reflection::Field* absl_nullable field = self.GetFieldById(id);
        if (field == nullptr) {
          absl::Format(out, "<unknown field: %d>", id);
        } else {
          VisitFlatbufferField(self.schema_, field,
                               PrinterVisitor{self, field_corpus, out, mode});
        }
        first = false;
      }
      absl::Format(out, "}");
    }
  };

  struct PrinterVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    const GenericDomainCorpusType& val;
    domain_implementor::RawSink out;
    domain_implementor::PrintMode mode;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) const {
      auto& domain = self.GetSubDomain<T>(field);
      absl::Format(out, "%s: ", field->name()->str());
      domain_implementor::PrintValue(domain, val, out, mode);
    }
  };
};

// Domain implementation for flatbuffers generated table classes.
// The corpus type is a pair of:
// - A map of field ids to field values.
// - The serialized buffer of the table.
template <typename T>
class FlatbuffersTableDomainImpl
    : public domain_implementor::DomainBase<
          // Derived, for CRTP needs. See DomainBase for more details.
          FlatbuffersTableDomainImpl<T>,
          // ValueType - user facing type, exact flatbuffer
          const T* absl_nonnull,
          // CorpusType - internal representation of ValueType
          std::pair<
              // Map of field ids to field values (note *Untyped*).
              typename FlatbuffersTableUntypedDomainImpl::corpus_type,
              //                       ^^^^^^^
              // Serialized flatbuffer.
              std::vector<uint8_t>>> {
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

  FlatbuffersTableDomainImpl(const FlatbuffersTableDomainImpl& other)
      : inner_(other.inner_) {
    builder_.Clear();
  }

  FlatbuffersTableDomainImpl& operator=(
      const FlatbuffersTableDomainImpl& other) {
    if (this == &other) return *this;
    inner_ = other.inner_;
    builder_.Clear();
    return *this;
  }

  FlatbuffersTableDomainImpl(FlatbuffersTableDomainImpl&& other)
      : inner_(std::move(other.inner_)) {
    builder_.Clear();
  }

  FlatbuffersTableDomainImpl& operator=(FlatbuffersTableDomainImpl&& other) {
    if (this == &other) return *this;
    inner_ = std::move(other.inner_);
    builder_.Clear();
    return *this;
  }

  // Initializes the table with random values.
  corpus_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;

    // Create new map of field ids to field values
    auto val = inner_->Init(prng);
    // Serialize the map into a flatbuffer
    auto offset = inner_->BuildTable(val, builder_);
    builder_.Finish(flatbuffers::Offset<flatbuffers::Table>(offset));
    // Store the serialized buffer in a vector.
    auto buffer =
        std::vector<uint8_t>(builder_.GetBufferPointer(),
                             builder_.GetBufferPointer() + builder_.GetSize());
    builder_.Clear();

    // Return corpus value: pair of the map and the serialized buffer.
    return std::make_pair(val, std::move(buffer));
  }

  // Returns the number of fields in the table.
  uint64_t CountNumberOfFields(corpus_type& val) {
    return inner_->CountNumberOfFields(val.first);
  }

  // Mutates the given corpus value.
  void Mutate(corpus_type& val, absl::BitGenRef prng,
              const domain_implementor::MutationMetadata& metadata,
              bool only_shrink) {
    // Modify values in the map.
    inner_->Mutate(val.first, prng, metadata, only_shrink);
    // Serialize the map into a flatbuffer and store it in vector
    val.second = BuildBuffer(val.first);
  }

  // Converts corpus value into the exact flatbuffer.
  value_type GetValue(const corpus_type& value) const {
    return flatbuffers::GetRoot<T>(value.second.data());
  }

  // Creates corpus value from the exact flatbuffer.
  std::optional<corpus_type> FromValue(const value_type& value) const {
    auto val = inner_->FromValue((const flatbuffers::Table*)value);
    if (!val.has_value()) return std::nullopt;
    return std::make_optional(std::make_pair(*val, BuildBuffer(*val)));
  }

  // Returns the printer for the table.
  auto GetPrinter() const { return Printer{*inner_}; }

  // Returns the parsed corpus value.
  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    auto val = inner_->ParseCorpus(obj);
    if (!val.has_value()) return std::nullopt;
    return std::make_optional(std::make_pair(*val, BuildBuffer(*val)));
  }

  // Returns the serialized corpus value.
  IRObject SerializeCorpus(const corpus_type& corpus_value) const {
    return inner_->SerializeCorpus(corpus_value.first);
  }

  // Returns the status of the given corpus value.
  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const {
    return inner_->ValidateCorpusValue(corpus_value.first);
  }

 private:
  std::optional<FlatbuffersTableUntypedDomainImpl> inner_;
  mutable flatbuffers::FlatBufferBuilder builder_;

  struct Printer {
    const FlatbuffersTableUntypedDomainImpl& inner;

    void PrintCorpusValue(const corpus_type& value,
                          domain_implementor::RawSink out,
                          domain_implementor::PrintMode mode) const {
      inner.GetPrinter().PrintCorpusValue(value.first, out, mode);
    }
  };

  std::vector<uint8_t> BuildBuffer(
      const typename corpus_type::first_type& val) const {
    auto offset = inner_->BuildTable(val, builder_);
    builder_.Finish(flatbuffers::Offset<flatbuffers::Table>(offset));
    auto buffer =
        std::vector<uint8_t>(builder_.GetBufferPointer(),
                             builder_.GetBufferPointer() + builder_.GetSize());
    builder_.Clear();
    return buffer;
  }
};

template <typename T>
class ArbitraryImpl<T, std::enable_if_t<is_flatbuffers_table_v<T>>>
    : public FlatbuffersTableDomainImpl<T> {};

}  // namespace fuzztest::internal
#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FLATBUFFERS_DOMAIN_IMPL_H_
