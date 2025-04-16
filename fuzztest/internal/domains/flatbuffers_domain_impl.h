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
#include <cassert>
#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
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
auto VisitFlatbufferField(const Field* field, Visitor visitor) {
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

// Flatbuffers enum domain implementation.
template <typename Underlaying>
class FlatbuffersEnumDomainImpl : public ElementOfImpl<Underlaying> {
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
      values.push_back(value->value());
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

// Domain implementation for flatbuffers generated table classes.
// It requires the corresponding reflection schema to be passed in the
// constructor.
// The Generated table class is the class that is generated by the flatbuffers
// compiler, and is used to access the fields of the table.
// The corpus type is a pair of:
// - A map of field ids to field values.
// - The serialized buffer of the table.
template <typename Generated>
class FlatbuffersTableImpl
    : public domain_implementor::DomainBase<
          FlatbuffersTableImpl<Generated>, const Generated*,
          std::pair<
              absl::flat_hash_map<
                  decltype(static_cast<reflection::Field*>(nullptr)->id()),
                  GenericDomainCorpusType>,
              std::vector<uint8_t>>> {
 public:
  static_assert(Requires<const Generated*>(
                    [](auto) -> decltype(Generated::BinarySchema::data()) {}),
                "The flatbuffers generated class must be generated with the "
                "`--bfbs-gen-embed` flag.");
  static_assert(Requires<const Generated*>(
                    [](auto) -> decltype(Generated::GetFullyQualifiedName()) {
                    }),
                "The flatbuffers generated class must be generated with the "
                "`--gen-name-strings` flag.");

  using typename FlatbuffersTableImpl::DomainBase::corpus_type;
  using typename FlatbuffersTableImpl::DomainBase::value_type;
  using FieldIdT = typename corpus_type::first_type::key_type;

  FlatbuffersTableImpl() {
    flatbuffers::Verifier verifier(Generated::BinarySchema::data(),
                                   Generated::BinarySchema::size());
    FUZZTEST_INTERNAL_CHECK(reflection::VerifySchemaBuffer(verifier),
                            "Invalid schema for flatbuffers table.");
    schema_ = reflection::GetSchema(Generated::BinarySchema::data());
    table_object_ =
        schema_->objects()->LookupByKey(Generated::GetFullyQualifiedName());
  }

  FlatbuffersTableImpl(const FlatbuffersTableImpl& other)
      : schema_(other.schema_), table_object_(other.table_object_) {
    absl::MutexLock l(&other.mutex_);
    domains_ = other.domains_;
  }

  FlatbuffersTableImpl& operator=(const FlatbuffersTableImpl& other) {
    schema_ = other.schema_;
    table_object_ = other.table_object_;
    absl::MutexLock l(&other.mutex_);
    domains_ = other.domains_;
    return *this;
  }

  FlatbuffersTableImpl(FlatbuffersTableImpl&& other)
      : schema_(other.schema_), table_object_(other.table_object_) {
    absl::MutexLock l(&other.mutex_);
    domains_ = std::move(other.domains_);
  }

  FlatbuffersTableImpl& operator=(FlatbuffersTableImpl&& other) {
    schema_ = other.schema_;
    table_object_ = other.table_object_;
    absl::MutexLock l(&other.mutex_);
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
    UpdateCorpusBuffer(val);
    return val;
  }

  // Mutates the corpus value.
  void Mutate(corpus_type& val, absl::BitGenRef prng,
              const domain_implementor::MutationMetadata& metadata,
              bool only_shrink) {
    using FieldsSizeT = decltype(table_object_->fields()->size());
    std::vector<FieldIdT> supported_fields;
    for (FieldsSizeT i = 0; i < table_object_->fields()->size(); ++i) {
      auto field = table_object_->fields()->Get(i);
      if (IsTypeSupported(field->type()->base_type())) {
        supported_fields.push_back(i);
      }
    }
    if (supported_fields.empty()) return;

    FieldIdT selected_field_index =
        absl::Uniform(prng, 0ul, supported_fields.size());

    MutateSelectedField(val, prng, metadata, only_shrink,
                        supported_fields[selected_field_index]);
  }

  // Mutates the selected field.
  uint64_t MutateSelectedField(
      corpus_type& val, absl::BitGenRef prng,
      const domain_implementor::MutationMetadata& metadata, bool only_shrink,
      FieldIdT selected_field_index) {
    const reflection::Field* field =
        table_object_->fields()->Get(selected_field_index);
    VisitFlatbufferField(
        field, MutateVisitor{*this, prng, metadata, only_shrink, val});
    UpdateCorpusBuffer(val);
    return 1;
  }

  auto GetPrinter() const { return Printer{*this}; }

  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const {
    for (const auto& [id, field_corpus] : corpus_value.first) {
      const reflection::Field* field = GetFieldById(id);
      if (field == nullptr) continue;
      absl::Status result;
      VisitFlatbufferField(field,
                           ValidateVisitor{*this, &field_corpus, result});
      if (!result.ok()) return result;
    }
    return absl::OkStatus();
  }

  value_type GetValue(const corpus_type& value) const {
    return flatbuffers::GetRoot<Generated>(value.second.data());
  }

  // Converts the table pointer to a corpus value.
  std::optional<corpus_type> FromValue(const value_type& value) const {
    using FieldsSizeT = decltype(table_object_->fields()->size());
    if (value == nullptr) {
      return std::nullopt;
    }
    corpus_type ret;
    for (FieldsSizeT i = 0; i < table_object_->fields()->size(); ++i) {
      const auto* field = table_object_->fields()->Get(i);
      VisitFlatbufferField(field, FromValueVisitor{*this, value, ret});
    }
    UpdateCorpusBuffer(ret);
    return ret;
  }

  // Converts the IRObject to a corpus value.
  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    corpus_type out;
    auto subs = obj.Subs();
    if (!subs) {
      return std::nullopt;
    }
    out.first.reserve(subs->size());
    for (const auto& sub : *subs) {
      auto pair_subs = sub.Subs();
      if (!pair_subs || pair_subs->size() != 2) {
        return std::nullopt;
      }
      auto id = (*pair_subs)[0].GetScalar<FieldIdT>();
      if (!id.has_value()) {
        return std::nullopt;
      }
      const reflection::Field* field = GetFieldById(id.value());
      if (field == nullptr) {
        return std::nullopt;
      }
      std::optional<GenericDomainCorpusType> inner_parsed;
      VisitFlatbufferField(field,
                           ParseVisitor{*this, (*pair_subs)[1], inner_parsed});
      if (!inner_parsed) {
        return std::nullopt;
      }
      out.first[id.value()] = *std::move(inner_parsed);
    }

    UpdateCorpusBuffer(out);
    return out;
  }

  // Converts the corpus value to an IRObject.
  IRObject SerializeCorpus(const corpus_type& value) const {
    IRObject out;
    auto& subs = out.MutableSubs();
    subs.reserve(value.first.size());
    for (const auto& [id, field_corpus] : value.first) {
      const reflection::Field* field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      IRObject& pair = subs.emplace_back();
      auto& pair_subs = pair.MutableSubs();
      pair_subs.reserve(2);
      pair_subs.emplace_back(field->id());
      VisitFlatbufferField(field, SerializeVisitor{*this, field_corpus,
                                                   pair_subs.emplace_back()});
    }
    return out;
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

  // Returns the domain for the given field.
  template <typename T>
  auto GetDomainForField(const reflection::Field* field) const {
    if constexpr (std::is_same_v<T, FlatbuffersArrayTag>) {
      // TODO(b/399123660): Implement this.
      return Domain<std::optional<bool>>(OptionalOf(ArbitraryImpl<bool>()));
    } else if constexpr (is_flatbuffers_enum_tag_v<T>) {
      auto enum_object = schema_->enums()->Get(field->type()->index());
      auto domain =
          OptionalOf(FlatbuffersEnumDomainImpl<typename T::type>(enum_object));
      if (!field->optional()) {
        domain.SetWithoutNull();
      }
      return Domain<value_type_t<decltype(domain)>>{domain};
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
      auto domain = OptionalOf(ArbitraryImpl<T>());
      if (!field->optional()) {
        domain.SetWithoutNull();
      }
      return Domain<std::optional<T>>{domain};
    }
  }

 private:
  const reflection::Schema* schema_;
  const reflection::Object* table_object_;
  mutable absl::Mutex mutex_;
  mutable absl::flat_hash_map<FieldIdT, CopyableAny> domains_
      ABSL_GUARDED_BY(mutex_);

  const reflection::Field* GetFieldById(FieldIdT id) const {
    const auto it =
        absl::c_find_if(*table_object_->fields(),
                        [id](const auto* field) { return field->id() == id; });
    return it != table_object_->fields()->end() ? *it : nullptr;
  }

  bool IsScalarType(reflection::BaseType base_type) const {
    switch (base_type) {
      case reflection::BaseType::Bool:
      case reflection::BaseType::Byte:
      case reflection::BaseType::Short:
      case reflection::BaseType::Int:
      case reflection::BaseType::Long:
      case reflection::BaseType::UByte:
      case reflection::BaseType::UShort:
      case reflection::BaseType::UInt:
      case reflection::BaseType::ULong:
      case reflection::BaseType::Float:
      case reflection::BaseType::Double:
        return true;
      default:
        return false;
    }
  }

  bool IsTypeSupported(reflection::BaseType base_type) const {
    return IsScalarType(base_type) || base_type == reflection::BaseType::String;
  }

  void UpdateCorpusBuffer(corpus_type& value) const {
    // TODO(b/399123660): The builder may come from a parent domain in case this
    // is a nested table.
    flatbuffers::FlatBufferBuilder builder;

    // Add all the fields to the builder.
    std::unordered_map<FieldIdT, flatbuffers::uoffset_t> offsets;
    for (const auto& [id, field_corpus] : value.first) {
      const reflection::Field* field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      VisitFlatbufferField(field, TableFieldBuilderVisitor{
                                      *this, builder, offsets, field_corpus});
    }
    // Build the table.
    auto table_start = builder.StartTable();
    for (const auto& [id, field_corpus] : value.first) {
      const reflection::Field* field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      VisitFlatbufferField(
          field, TableBuilderVisitor{*this, builder, offsets, field_corpus});
    }
    auto table_offset = builder.EndTable(table_start);
    builder.template Finish<flatbuffers::Table>(table_offset, nullptr);

    // copy the buffer to the corpus value.
    value.second =
        std::vector<uint8_t>(builder.GetBufferPointer(),
                             builder.GetBufferPointer() + builder.GetSize());
  }

  struct SerializeVisitor {
    const FlatbuffersTableImpl& self;
    const GenericDomainCorpusType& corpus_value;
    IRObject& out;

    template <typename T>
    void Visit(const reflection::Field* field) {
      out = self.GetSubDomain<T>(field).SerializeCorpus(corpus_value);
    }
  };

  struct FromValueVisitor {
    const FlatbuffersTableImpl& self;
    value_type value;
    corpus_type& out;

    template <typename T>
    void Visit(const reflection::Field* field) const {
      const flatbuffers::Table* table = (const flatbuffers::Table*)(value);
      [[maybe_unused]]
      reflection::BaseType base_type = field->type()->base_type();
      auto& domain = self.GetSubDomain<T>(field);
      value_type_t<std::decay_t<decltype(domain)>> inner_value;

      if constexpr (is_flatbuffers_enum_tag_v<T>) {
        assert(base_type >= reflection::BaseType::Byte &&
               base_type <= reflection::BaseType::ULong);
        if (field->optional() && !table->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value =
              std::make_optional(table->template GetField<typename T::type>(
                  field->offset(), field->default_integer()));
        }
      } else if constexpr (std::is_integral_v<T>) {
        assert(base_type >= reflection::BaseType::Bool &&
               base_type <= reflection::BaseType::ULong);
        if (field->optional() && !table->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::make_optional(table->template GetField<T>(
              field->offset(), field->default_integer()));
        }
      } else if constexpr (std::is_floating_point_v<T>) {
        assert(base_type >= reflection::BaseType::Float &&
               base_type <= reflection::BaseType::Double);
        if (field->optional() && !table->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::make_optional(table->template GetField<T>(
              field->offset(), field->default_real()));
        }
      } else if constexpr (std::is_same_v<T, std::string>) {
        assert(base_type == reflection::BaseType::String);
        if (!table->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::make_optional(
              table->template GetPointer<flatbuffers::String*>(field->offset())
                  ->str());
        }
      }

      auto inner = domain.FromValue(inner_value);
      if (inner) {
        out.first[field->id()] = *std::move(inner);
      }
    };
  };

  struct TableFieldBuilderVisitor {
    const FlatbuffersTableImpl& self;
    flatbuffers::FlatBufferBuilder& builder;
    std::unordered_map<FieldIdT, flatbuffers::uoffset_t>& offsets;
    const typename corpus_type::first_type::value_type::second_type&
        corpus_value;

    template <typename T>
    void Visit(const reflection::Field* field) const {
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

  struct TableBuilderVisitor {
    const FlatbuffersTableImpl& self;
    flatbuffers::FlatBufferBuilder& builder;
    std::unordered_map<FieldIdT, flatbuffers::uoffset_t>& offsets;
    const typename corpus_type::first_type::value_type::second_type&
        corpus_value;

    template <typename T>
    void Visit(const reflection::Field* field) const {
      auto size = flatbuffers::GetTypeSize(field->type()->base_type());
      if constexpr (std::is_integral_v<T> || std::is_floating_point_v<T> ||
                    is_flatbuffers_enum_tag_v<T>) {
        auto& domain = self.GetSubDomain<T>(field);
        auto v = domain.GetValue(corpus_value);
        if (!v) {
          return;
        }
        builder.Align(size);
        builder.PushBytes(reinterpret_cast<const uint8_t*>(&v), size);
        builder.TrackField(field->offset(), builder.GetSize());
      } else if constexpr (std::is_same_v<T, std::string>) {
        if (auto it = offsets.find(field->id()); it != offsets.end()) {
          builder.AddOffset(
              field->offset(),
              flatbuffers::Offset<flatbuffers::String>(it->second));
        }
      }
    }
  };

  struct ParseVisitor {
    const FlatbuffersTableImpl& self;
    const IRObject& obj;
    std::optional<GenericDomainCorpusType>& out;

    template <typename T>
    void Visit(const reflection::Field* field) {
      out = self.GetSubDomain<T>(field).ParseCorpus(obj);
    }
  };

  struct ValidateVisitor {
    const FlatbuffersTableImpl& self;
    const GenericDomainCorpusType* corpus_value;
    absl::Status& out;

    template <typename T>
    void Visit(const reflection::Field* field) {
      auto& domain = self.GetSubDomain<T>(field);
      if (corpus_value != nullptr) {  // Field is set.
        out = domain.ValidateCorpusValue(*corpus_value);
      } else {
        out = domain.ValidateCorpusValue(*domain.FromValue(std::nullopt));
      }
      if (!out.ok()) {
        out = Prefix(out, absl::StrCat("Invalid value for field ",
                                       field->name()->str()));
      }
    }
  };

  struct InitializeVisitor {
    FlatbuffersTableImpl& self;
    absl::BitGenRef prng;
    corpus_type& val;

    template <typename T>
    void Visit(const reflection::Field* field) {
      auto& domain = self.GetSubDomain<T>(field);
      val.first[field->id()] = domain.Init(prng);
    }
  };

  struct MutateVisitor {
    FlatbuffersTableImpl& self;
    absl::BitGenRef prng;
    const domain_implementor::MutationMetadata& metadata;
    bool only_shrink;
    corpus_type& val;

    template <typename T>
    void Visit(const reflection::Field* field) {
      auto& domain = self.GetSubDomain<T>(field);
      if (auto it = val.first.find(field->id()); it != val.first.end()) {
        domain.Mutate(it->second, prng, metadata, only_shrink);
      } else if (!only_shrink) {
        val.first[field->id()] = domain.Init(prng);
      }
    }
  };

  struct Printer {
    const FlatbuffersTableImpl& self;

    void PrintCorpusValue(const corpus_type& value,
                          domain_implementor::RawSink out,
                          domain_implementor::PrintMode mode) const {
      absl::Format(out, "{");
      bool first = true;
      for (const auto& [id, field_corpus] : value.first) {
        if (!first) {
          absl::Format(out, ", ");
        }
        const reflection::Field* field = self.GetFieldById(id);
        if (field == nullptr) {
          absl::Format(out, "<unknown field: %d>", id);
        } else {
          VisitFlatbufferField(field,
                               PrinterVisitor{self, field_corpus, out, mode});
        }
        first = false;
      }
      absl::Format(out, "}");
    }
  };

  struct PrinterVisitor {
    const FlatbuffersTableImpl& self;
    const GenericDomainCorpusType& val;
    domain_implementor::RawSink out;
    domain_implementor::PrintMode mode;

    template <typename T>
    void Visit(const reflection::Field* field) const {
      auto& domain = self.GetSubDomain<T>(field);
      absl::Format(out, "%s: ", field->name()->str());
      domain_implementor::PrintValue(domain, val, out, mode);
    }
  };
};

template <typename T>
class ArbitraryImpl<T, std::enable_if_t<is_flatbuffers_table_v<T>>>
    : public FlatbuffersTableImpl<T> {};
}  // namespace fuzztest::internal
#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FLATBUFFERS_DOMAIN_IMPL_H_
