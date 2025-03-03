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
#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
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
#include "flatbuffers/table.h"
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

struct FlatbuffersArrayTag;
struct FlatbuffersObjTag;
struct FlatbuffersUnionTag;
struct FlatbuffersVectorTag;

// Dynamic to static dispatch visitor pattern.
template <typename Field, typename Visitor>
auto VisitFlatbufferField(const Field* absl_nonnull field, Visitor visitor) {
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
      visitor.template Visit<FlatbuffersVectorTag>(field);
      break;
    case reflection::BaseType::Array:
      visitor.template Visit<FlatbuffersArrayTag>(field);
      break;
    case reflection::BaseType::Obj:
      visitor.template Visit<FlatbuffersObjTag>(field);
      break;
    case reflection::BaseType::Union:
      visitor.template Visit<FlatbuffersUnionTag>(field);
      break;
    default:
      FUZZTEST_INTERNAL_CHECK(false, "Unsupported base type");
  }
}

// Domain implementation for flatbuffers untyped tables.
// The corpus type is a map of field ids to field values.
class FlatbuffersTableUntypedDomainImpl
    : public fuzztest::domain_implementor::DomainBase<
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
              fuzztest::GenericDomainCorpusType>> {
 public:
  using typename FlatbuffersTableUntypedDomainImpl::DomainBase::corpus_type;
  using typename FlatbuffersTableUntypedDomainImpl::DomainBase::value_type;
  using FieldIdT = typename corpus_type::key_type;

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
      VisitFlatbufferField(field, InitializeVisitor{*this, prng, val});
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
      // For enums, build the list of valid labels.
      std::vector<typename T::type> values;
      values.reserve(enum_object->values()->size());
      for (const auto* value : *enum_object->values()) {
        values.push_back(value->value());
      }
      // Delay instantiation. The Domain class is not fully defined at this
      // point yet, and neither is ElementOfImpl.
      using LazyInt = MakeDependentType<typename T::type, T>;
      auto domain = OptionalOf(ElementOfImpl<LazyInt>(std::move(values)));
      if (!field->optional()) {
        domain.SetWithoutNull();
      }
      return Domain<std::optional<LazyInt>>{domain};
    } else if constexpr (std::is_same_v<T, FlatbuffersObjTag>) {
      // TODO(b/399123660): Implement this.
      return Domain<std::optional<bool>>(OptionalOf(ArbitraryImpl<bool>()));
    } else if constexpr (std::is_same_v<T, FlatbuffersUnionTag>) {
      // TODO(b/399123660): Implement this.
      return Domain<std::optional<bool>>(OptionalOf(ArbitraryImpl<bool>()));
    } else if constexpr (std::is_same_v<T, FlatbuffersVectorTag>) {
      // TODO(b/399123660): Implement this.
      return Domain<std::optional<bool>>(OptionalOf(ArbitraryImpl<bool>()));
    } else {
      auto inner = OptionalOf(ArbitraryImpl<T>());
      if (!field->optional()) {
        inner.SetWithoutNull();
      }
      return Domain<std::optional<T>>{inner};
    }
  }

  // Returns the domain for the given field.
  // The domain is cached, and the same instance is returned for the same field.
  template <typename T>
  auto& GetSubDomain(const reflection::Field* field) const {
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
  uint64_t CountNumberOfFields(corpus_type& val) {
    uint64_t total_weight = 0;
    for (const auto* field : *table_object_->fields()) {
      reflection::BaseType base_type = field->type()->base_type();
      if (flatbuffers::IsScalar(base_type)) {
        ++total_weight;
      } else if (base_type == reflection::BaseType::String) {
        ++total_weight;
      }
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
            field, MutateVisitor{*this, prng, metadata, only_shrink, val});
        return field_counter;
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
      VisitFlatbufferField(field, ValidateVisitor{*this, field_corpus, result});
      if (!result.ok()) return result;
    }
    return absl::OkStatus();
  }

  value_type GetValue(const corpus_type& value) const {
    FUZZTEST_INTERNAL_CHECK(false,
                            "GetValue is not supported for flatbuffers.");
    // Untyped domain does not support GetValue since if it is a nested table it
    // would need the top level table corpus value to be able to build it.
    return nullptr;
  }

  // Converts the table pointer to a corpus value.
  std::optional<corpus_type> FromValue(const value_type& value) const {
    if (value == nullptr) {
      return std::nullopt;
    }
    corpus_type ret;
    for (const auto* field : *table_object_->fields()) {
      VisitFlatbufferField(field, FromValueVisitor{*this, value, ret});
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
      auto id = (*pair_subs)[0].GetScalar<FieldIdT>();
      if (!id.has_value()) {
        return std::nullopt;
      }

      // Get information about the field from reflection.
      const reflection::Field* absl_nullable field = GetFieldById(id.value());
      if (field == nullptr) {
        return std::nullopt;
      }

      // Deserialize the field corpus value.
      std::optional<GenericDomainCorpusType> inner_parsed;
      VisitFlatbufferField(field,
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
      VisitFlatbufferField(field, SerializeVisitor{*this, field_corpus,
                                                   pair_subs.emplace_back()});
    }
    return out;
  }

  uint32_t BuildTable(const corpus_type& value,
                      flatbuffers::FlatBufferBuilder& builder) const {
    // Add all the fields to the builder.

    // Offsets is the map of field id to its offset in the table.
    absl::flat_hash_map<FieldIdT, flatbuffers::uoffset_t> offsets;

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
      VisitFlatbufferField(field, TableFieldBuilderVisitor{
                                      *this, builder, offsets, field_corpus});
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
          field, TableBuilderVisitor{*this, builder, offsets, field_corpus});
    }
    return builder.EndTable(table_start);
  }

 private:
  const reflection::Schema* absl_nonnull schema_;
  const reflection::Object* absl_nonnull table_object_;
  mutable absl::Mutex mutex_;
  mutable absl::flat_hash_map<FieldIdT, CopyableAny> domains_
      ABSL_GUARDED_BY(mutex_);

  const reflection::Field* absl_nullable GetFieldById(FieldIdT id) const {
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
          inner_value = std::optional(value->GetField<typename T::type>(
              field->offset(), field->default_integer()));
        }
      } else if constexpr (std::is_integral_v<T>) {
        FUZZTEST_INTERNAL_CHECK(base_type >= reflection::BaseType::Bool &&
                                    base_type <= reflection::BaseType::ULong,
                                "Field must be an integer type.");
        if (field->optional() && !value->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::optional(
              value->GetField<T>(field->offset(), field->default_integer()));
        }
      } else if constexpr (std::is_floating_point_v<T>) {
        FUZZTEST_INTERNAL_CHECK(base_type >= reflection::BaseType::Float &&
                                    base_type <= reflection::BaseType::Double,
                                "Field must be a floating point type.");
        if (field->optional() && !value->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::optional(
              value->GetField<T>(field->offset(), field->default_real()));
        }
      } else if constexpr (std::is_same_v<T, std::string>) {
        FUZZTEST_INTERNAL_CHECK(base_type == reflection::BaseType::String,
                                "Field must be a string type.");
        if (!value->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::optional(
              value->GetPointer<flatbuffers::String*>(field->offset())->str());
        }
      }

      auto inner = domain.FromValue(inner_value);
      if (inner) {
        out[field->id()] = *std::move(inner);
      }
    };
  };

  // Create out-of-line table fields, see `BuildTable` for details.
  struct TableFieldBuilderVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    flatbuffers::FlatBufferBuilder& builder;
    absl::flat_hash_map<FieldIdT, flatbuffers::uoffset_t>& offsets;
    const typename corpus_type::value_type::second_type& corpus_value;

    template <typename T>
    void Visit(const reflection::Field* absl_nonnull field) const {
      if constexpr (std::is_same_v<T, std::string>) {
        auto& domain = self.GetSubDomain<T>(field);
        auto user_value = domain.GetValue(corpus_value);
        if (user_value.has_value()) {
          auto offset =
              builder.CreateString(user_value->data(), user_value->size()).o;
          offsets.insert({field->id(), offset});
        }
      }
    }
  };

  // Create complete table: store "inline fields" values inline, and store just
  // offsets for "out-of-line fields". See `BuildTable` for details.
  struct TableBuilderVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    flatbuffers::FlatBufferBuilder& builder;
    const absl::flat_hash_map<FieldIdT, flatbuffers::uoffset_t>& offsets;
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
      } else if constexpr (std::is_same_v<T, std::string>) {
        // "Out-of-line field". Store just offset.
        if (auto it = offsets.find(field->id()); it != offsets.end()) {
          builder.AddOffset(
              field->offset(),
              flatbuffers::Offset<flatbuffers::String>(it->second));
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
      std::vector<FieldIdT> field_ids;
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
          VisitFlatbufferField(field,
                               PrinterVisitor{self, value.at(id), out, mode});
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

// Corpus type for the table domain
struct FlatbuffersTableDomainCorpusType {
  // Map of field ids to field values.
  typename FlatbuffersTableUntypedDomainImpl::corpus_type untyped_corpus;
  // Serialized flatbuffer.
  std::vector<uint8_t> buffer;
};

// Domain implementation for flatbuffers generated table classes.
// The corpus type is a pair of:
// - A map of field ids to field values.
// - The serialized buffer of the table.
template <typename T>
class FlatbuffersTableDomainImpl
    : public fuzztest::domain_implementor::DomainBase<
          // Derived, for CRTP needs. See DomainBase for more details.
          FlatbuffersTableDomainImpl<T>,
          // ValueType - user facing type, exact flatbuffer
          const T* absl_nonnull,
          // CorpusType - internal representation of ValueType
          FlatbuffersTableDomainCorpusType> {
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
    return FlatbuffersTableDomainCorpusType{val, std::move(buffer)};
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
    // Serialize the map into a flatbuffer and store it in vector
    val.buffer = BuildBuffer(val.untyped_corpus);
  }

  // Converts corpus value into the exact flatbuffer.
  value_type GetValue(const corpus_type& value) const {
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
  mutable flatbuffers::FlatBufferBuilder builder_;

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
