#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FLATBUFFERS_DOMAIN_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FLATBUFFERS_DOMAIN_IMPL_H_

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <list>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
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

template <typename T>
using remove_pointer_cv_t = std::remove_cv_t<std::remove_pointer_t<T>>;

// Get the `reflection::Object` type from the `reflection::Schema` type.
template <typename Schema>
using get_object_t = remove_pointer_cv_t<typename remove_pointer_cv_t<
    std::invoke_result_t<decltype(&Schema::objects), Schema>>::value_type>;

// Get the `reflection::Field` type from the `reflection::Object` type.
template <typename Object>
using get_field_t = remove_pointer_cv_t<typename remove_pointer_cv_t<
    std::invoke_result_t<decltype(&Object::fields), Object>>::value_type>;

// Get the `flatbuffers::String` type from the `reflection::Object` type.
template <typename Object>
using get_string_t =
    remove_pointer_cv_t<std::invoke_result_t<decltype(&Object::name), Object>>;

// Get the `reflection::BaseType` type from the `reflection::Field` type.
template <typename Field>
struct get_base_type {
 private:
  using type =
      remove_pointer_cv_t<std::invoke_result_t<decltype(&Field::type), Field>>;

 public:
  using base_type = remove_pointer_cv_t<
      std::invoke_result_t<decltype(&type::base_type), type>>;
};
// Get the `reflection::BaseType` type from the `reflection::Field` type.
template <typename Field>
using get_base_type_t = typename get_base_type<Field>::base_type;

// Deduct the `flatbuffers::FlatbufferBuilder` type from the Generated type.
template <typename Generated>
using get_builder_t = std::decay_t<decltype(Generated::Builder::fbb_)>;

// Get the field id type from the `reflection::Field` type.
template <typename Field>
using get_field_id_t = std::remove_cv_t<
    std::remove_pointer_t<std::invoke_result_t<decltype(&Field::id), Field>>>;

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
struct FlatbuffersTableTag;
struct FlatbuffersStructTag;
struct FlatbuffersUnionTag;

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

// Dynamic to static dispatch visitor pattern for flatbuffers vector elements.
template <typename Schema, typename BaseType, typename Field, typename Visitor>
auto VisitFlatbuffersVectorElementField(const Schema* schema,
                                        const Field* field, Visitor visitor) {
  auto field_index = field->type()->index();
  auto element_type = field->type()->element();
  switch (element_type) {
    case BaseType::Bool:
      visitor.template Visit<FlatbuffersVectorTag<bool>>(field);
      break;
    case BaseType::Byte:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<int8_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<int8_t>>(field);
      }
      break;
    case BaseType::Short:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<int16_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<int16_t>>(field);
      }
      break;
    case BaseType::Int:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<int32_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<int32_t>>(field);
      }
      break;
    case BaseType::Long:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<int64_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<int64_t>>(field);
      }
      break;
    case BaseType::UByte:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<uint8_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<uint8_t>>(field);
      }
      break;
    case BaseType::UShort:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<uint16_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<uint16_t>>(field);
      }
      break;
    case BaseType::UInt:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<uint32_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<uint32_t>>(field);
      }
      break;
    case BaseType::ULong:
      if (field_index >= 0) {
        visitor
            .template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<uint64_t>>>(
                field);
      } else {
        visitor.template Visit<FlatbuffersVectorTag<uint64_t>>(field);
      }
      break;
    case BaseType::Float:
      visitor.template Visit<FlatbuffersVectorTag<float>>(field);
      break;
    case BaseType::Double:
      visitor.template Visit<FlatbuffersVectorTag<double>>(field);
      break;
    case BaseType::String:
      visitor.template Visit<FlatbuffersVectorTag<std::string>>(field);
      break;
    case BaseType::Obj: {
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
    case BaseType::Union:
      visitor.template Visit<FlatbuffersVectorTag<FlatbuffersUnionTag>>(field);
      break;
    case BaseType::UType:
      visitor.template Visit<FlatbuffersVectorTag<FlatbuffersEnumTag<uint8_t>>>(
          field);
      break;
    default:  // Vector of vectors and vector of arrays are not supported.
      FUZZTEST_INTERNAL_CHECK(false, "Unsupported vector base type");
  }
}

template <typename Schema, typename Field, typename Visitor>
auto VisitFlatbuffersField(const Schema* schema, const Field* field,
                           Visitor visitor) {
  using BaseType = get_base_type_t<Field>;

  auto field_index = field->type()->index();
  switch (field->type()->base_type()) {
    case BaseType::Bool:
      visitor.template Visit<bool>(field);
      break;
    case BaseType::Byte:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<int8_t>>(field);
      } else {
        visitor.template Visit<int8_t>(field);
      }
      break;
    case BaseType::Short:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<int16_t>>(field);
      } else {
        visitor.template Visit<int16_t>(field);
      }
      break;
    case BaseType::Int:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<int32_t>>(field);
      } else {
        visitor.template Visit<int32_t>(field);
      }
      break;
    case BaseType::Long:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<int64_t>>(field);
      } else {
        visitor.template Visit<int64_t>(field);
      }
      break;
    case BaseType::UByte:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<uint8_t>>(field);
      } else {
        visitor.template Visit<uint8_t>(field);
      }
      break;
    case BaseType::UShort:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<uint16_t>>(field);
      } else {
        visitor.template Visit<uint16_t>(field);
      }
      break;
    case BaseType::UInt:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<uint32_t>>(field);
      } else {
        visitor.template Visit<uint32_t>(field);
      }
      break;
    case BaseType::ULong:
      if (field_index >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<uint64_t>>(field);
      } else {
        visitor.template Visit<uint64_t>(field);
      }
      break;
    case BaseType::Float:
      visitor.template Visit<float>(field);
      break;
    case BaseType::Double:
      visitor.template Visit<double>(field);
      break;
    case BaseType::String:
      visitor.template Visit<std::string>(field);
      break;
    case BaseType::Vector:
    case BaseType::Vector64: {
      VisitFlatbuffersVectorElementField<Schema, BaseType, Field, Visitor>(
          schema, field, visitor);
      break;
    }
    case BaseType::Array:
      visitor.template Visit<FlatbuffersArrayTag>(field);
      break;
    case BaseType::Obj: {
      auto sub_object = schema->objects()->Get(field->type()->index());
      if (sub_object->is_struct()) {
        visitor.template Visit<FlatbuffersStructTag>(field);
      } else {
        visitor.template Visit<FlatbuffersTableTag>(field);
      }
      break;
    }
    case BaseType::Union:
      visitor.template Visit<FlatbuffersUnionTag>(field);
      break;
    case BaseType::UType:
      visitor.template Visit<FlatbuffersEnumTag<uint8_t>>(field);
      break;
    default:
      FUZZTEST_INTERNAL_CHECK(false, "Unsupported base type");
  }
}

// The FlatbuffersToolbox is a struct that allows to access the flatbuffers
// without depending on the flatbuffers library.
// It is typically defined as follows:
//    struct FlatbuffersToolbox {
//      using base_type = reflection::BaseType;
//      using builder_type = flatbuffers::FlatBufferBuilder;
//      using schema_type = reflection::Schema;
//      using table_type = flatbuffers::Table;
//      using verifier_type = flatbuffers::Verifier;
//      template <typename T = void>
//      using offset_type = flatbuffers::Offset<T>;
//
//      static size_t GetTypeSize(const base_type& type) {
//        return flatbuffers::GetTypeSize(type);
//      }
//
//      template <typename T>
//      static const T* GetRoot(const void* buf) {
//        return flatbuffers::GetRoot<T>(buf);
//      }
//
//      static bool VerifySchemaBuffer(verifier_type& verifier) {
//        return reflection::VerifySchemaBuffer(verifier);
//      }
//    };
template <typename FlatbuffersToolbox>
constexpr bool is_valid_toolbox_t() {
  static_assert(
      Requires<FlatbuffersToolbox>([](auto toolbox) ->
                                   typename FlatbuffersToolbox::base_type {}),
      "FlatbuffersToolbox must have a base_type.");
  static_assert(
      Requires<FlatbuffersToolbox>([](auto toolbox) ->
                                   typename FlatbuffersToolbox::table_type {}),
      "FlatbuffersToolbox must have a table_type.");
  static_assert(
      Requires<FlatbuffersToolbox>([](auto toolbox) ->
                                   typename FlatbuffersToolbox::schema_type {}),
      "FlatbuffersToolbox must have a schema_type.");
  static_assert(
      Requires<FlatbuffersToolbox>(
          [](auto toolbox) -> typename FlatbuffersToolbox::builder_type {}),
      "FlatbuffersToolbox must have a builder_type.");
  static_assert(
      Requires<FlatbuffersToolbox>(
          [](auto toolbox) -> typename FlatbuffersToolbox::verifier_type {}),
      "FlatbuffersToolbox must have a verifier_type.");
  static_assert(Requires<FlatbuffersToolbox>(
                    [](auto toolbox) ->
                    typename FlatbuffersToolbox::template offset_type<void> {}),
                "FlatbuffersToolbox must have an offset_type.");
  static_assert(
      Requires<FlatbuffersToolbox>(
          [](auto toolbox)
              -> decltype(toolbox.GetTypeSize(
                  std::declval<typename FlatbuffersToolbox::base_type>())) {}),
      "FlatbuffersToolbox must have a GetTypeSize method.");
  static_assert(
      Requires<FlatbuffersToolbox>(
          [](auto toolbox)
              -> decltype(toolbox.template GetRoot<
                          typename FlatbuffersToolbox::table_type>(
                  std::declval<
                      const typename FlatbuffersToolbox::table_type*>())) {}),
      "FlatbuffersToolbox must have a GetRoot method.");
  static_assert(
      Requires<FlatbuffersToolbox>(
          [](auto toolbox)
              -> decltype(toolbox.VerifySchemaBuffer(
                  std::declval<
                      typename FlatbuffersToolbox::verifier_type&>())) {}),
      "FlatbuffersToolbox must have a VerifySchemaBuffer method.");
  return true;
}
// Untyped domain implementation for flatbuffers generated table classes.
template <typename FlatbuffersToolbox,
          typename FieldIdT = get_field_id_t<get_field_t<
              get_object_t<typename FlatbuffersToolbox::schema_type>>>>
class FlatbuffersTableUntypedDomainImpl
    : public domain_implementor::DomainBase<
          FlatbuffersTableUntypedDomainImpl<FlatbuffersToolbox, FieldIdT>,
          const typename FlatbuffersToolbox::table_type*,
          absl::flat_hash_map<FieldIdT, GenericDomainCorpusType>> {
 public:
  static_assert(is_valid_toolbox_t<FlatbuffersToolbox>());
  using typename FlatbuffersTableUntypedDomainImpl::DomainBase::corpus_type;
  using typename FlatbuffersTableUntypedDomainImpl::DomainBase::value_type;
  using Builder = typename FlatbuffersToolbox::builder_type;
  using Schema = typename FlatbuffersToolbox::schema_type;
  using Table = typename FlatbuffersToolbox::table_type;
  using Object = get_object_t<Schema>;
  using Field = get_field_t<Object>;
  using String = get_string_t<Object>;
  using BaseType = get_base_type_t<Field>;
  template <typename T = void>
  using Offset = typename FlatbuffersToolbox::template offset_type<T>;
  using UOffsetT = typename Offset<>::offset_type;
  template <typename T, typename SizeT = UOffsetT>
  using Vector = typename FlatbuffersToolbox::template vector_type<T, SizeT>;

  explicit FlatbuffersTableUntypedDomainImpl(const Schema* schema,
                                             const Object* table_object)
      : schema_(schema), table_object_(table_object) {}

  FlatbuffersTableUntypedDomainImpl(
      const FlatbuffersTableUntypedDomainImpl& other)
      : schema_(other.schema_), table_object_(other.table_object_) {
    absl::MutexLock l(&other.mutex_);
    domains_ = other.domains_;
  };

  FlatbuffersTableUntypedDomainImpl& operator=(
      const FlatbuffersTableUntypedDomainImpl& other) {
    schema_ = other.schema_;
    table_object_ = other.table_object_;
    absl::MutexLock l(&other.mutex_);
    domains_ = other.domains_;
    return *this;
  }

  FlatbuffersTableUntypedDomainImpl(FlatbuffersTableUntypedDomainImpl&& other)
      : schema_(other.schema_), table_object_(other.table_object_) {
    absl::MutexLock l(&other.mutex_);
    domains_ = std::move(other.domains_);
  }

  FlatbuffersTableUntypedDomainImpl& operator=(
      FlatbuffersTableUntypedDomainImpl&& other) {
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
      VisitFlatbuffersField(schema_, field,
                            InitializeVisitor{*this, prng, val});
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

  // Counts the number of fields that can be mutated.
  // Returns the number of fields in the flattened tree for supported field
  // types.
  uint64_t CountNumberOfFields(corpus_type& val) {
    uint64_t total_weight = 0;
    for (const auto* field : *table_object_->fields()) {
      BaseType base_type = field->type()->base_type();
      if (IsScalarType(base_type)) {
        ++total_weight;
      } else if (base_type == BaseType::String) {
        ++total_weight;
      } else if (base_type == BaseType::Obj) {
        ++total_weight;
        auto sub_object = schema_->objects()->Get(field->type()->index());
        if (!sub_object->is_struct()) {
          auto& sub_domain = GetSubDomain<FlatbuffersTableTag>(field);
          total_weight += sub_domain.CountNumberOfFields(val[field->id()]);
        }
      } else if (base_type == BaseType::Vector ||
                 base_type == BaseType::Vector64) {
        ++total_weight;
        auto elem_type = field->type()->element();
        if (IsScalarType(elem_type)) {
          ++total_weight;
        } else if (elem_type == BaseType::String) {
          ++total_weight;
        } else if (elem_type == BaseType::Obj) {
          ++total_weight;
          auto sub_object = schema_->objects()->Get(field->type()->index());
          if (!sub_object->is_struct()) {
            auto sub_domain =
                GetSubDomain<FlatbuffersVectorTag<FlatbuffersTableTag>>(field);
            total_weight += sub_domain.CountNumberOfFields(val[field->id()]);
          }
        }
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
        VisitFlatbuffersField(
            schema_, field,
            MutateVisitor{*this, prng, metadata, only_shrink, val});
        return field_counter;
      }

      auto base_type = field->type()->base_type();
      if (base_type == BaseType::Obj) {
        auto sub_object = schema_->objects()->Get(field->type()->index());
        if (!sub_object->is_struct()) {
          field_counter +=
              GetSubDomain<FlatbuffersTableTag>(field).MutateSelectedField(
                  val[field->id()], prng, metadata, only_shrink,
                  selected_field_index - field_counter);
        }
      }

      if (base_type == BaseType::Vector || base_type == BaseType::Vector64) {
        auto elem_type = field->type()->element();
        if (elem_type == BaseType::Obj) {
          auto sub_object = schema_->objects()->Get(field->type()->index());
          if (!sub_object->is_struct()) {
            field_counter +=
                GetSubDomain<FlatbuffersVectorTag<FlatbuffersTableTag>>(field)
                    .MutateSelectedField(val[field->id()], prng, metadata,
                                         only_shrink,
                                         selected_field_index - field_counter);
          }
        }
      }

      if (field_counter > selected_field_index) {
        return field_counter;
      }
    }
    return field_counter;
  }

  auto GetPrinter() const { return Printer{*this}; }

  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const {
    for (const auto& [id, data] : corpus_value) {
      const Field* field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      absl::Status result;
      VisitFlatbuffersField(schema_, field,
                            ValidateVisitor{*this, &data, result});
      if (!result.ok()) return result;
    }
    return absl::OkStatus();
  }

  value_type GetValue(const corpus_type& value) const {
    // Untyped domain does not support GetValue since if it is a nested table it
    // would need the top level table corpus value to be able to build it.
    return nullptr;
  }

  // Converts the table pointer to a corpus value.
  std::optional<corpus_type> FromValue(const value_type& value) const {
    corpus_type ret;
    for (const auto* field : *table_object_->fields()) {
      VisitFlatbuffersField(schema_, field,
                            FromValueVisitor{*this, value, ret});
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
    out.reserve(subs->size());
    for (const auto& sub : *subs) {
      auto pair_subs = sub.Subs();
      if (!pair_subs || pair_subs->size() != 2) {
        return std::nullopt;
      }
      auto id = (*pair_subs)[0].GetScalar<FieldIdT>();
      if (!id.has_value()) {
        return std::nullopt;
      }
      const Field* field = GetFieldById(id.value());
      if (field == nullptr) {
        return std::nullopt;
      }
      std::optional<GenericDomainCorpusType> inner_parsed;
      VisitFlatbuffersField(schema_, field,
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
    for (const auto& [id, field_corpus] : value) {
      const Field* field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      IRObject& pair = subs.emplace_back();
      auto& pair_subs = pair.MutableSubs();
      pair_subs.reserve(2);
      pair_subs.emplace_back(field->id());
      VisitFlatbuffersField(
          schema_, field,
          SerializeVisitor{*this, field_corpus, pair_subs.emplace_back()});
    }
    return out;
  }

  // Returns the domain for the given field.
  // The domain is cached, and the same instance is returned for the same field.
  template <typename T>
  auto& GetSubDomain(const Field* field) const {
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

  // Returns the domain for the given vector field.
  template <typename Element>
  auto GetDomainForVectorField(const Field* field) const {
    if constexpr (is_flatbuffers_enum_tag_v<Element>) {
      auto enum_object = schema_->enums()->Get(field->type()->index());
      // For enums, build the list of valid labels.
      std::vector<typename Element::type> values;
      values.reserve(enum_object->values()->size());
      for (const auto* value : *enum_object->values()) {
        values.push_back(value->value());
      }
      // Delay instantiation. The Domain class is not fully defined at this
      // point yet, and neither is ElementOfImpl.
      using LazyInt = MakeDependentType<typename Element::type, Element>;
      auto inner = OptionalOf(ContainerOf<std::vector<LazyInt>>(
          ElementOfImpl<LazyInt>(std::move(values))));
      if (!field->optional()) {
        inner.SetWithoutNull();
      }
      return Domain<std::optional<std::vector<LazyInt>>>{inner};
    } else if constexpr (std::is_same_v<Element, FlatbuffersTableTag>) {
      auto table_object = schema_->objects()->Get(field->type()->index());
      auto inner = OptionalOf(ContainerOf<std::vector<const Table*>>(
          FlatbuffersTableUntypedDomainImpl<FlatbuffersToolbox>{schema_,
                                                                table_object}));
      if (!field->optional()) {
        inner.SetWithoutNull();
      }
      return Domain<std::optional<std::vector<const Table*>>>{inner};
    } else if constexpr (std::is_same_v<Element, FlatbuffersStructTag>) {
      // TODO(b/399123660): implement this.
      return Domain<std::optional<bool>>(OptionalOf(ArbitraryImpl<bool>()));
    } else if constexpr (std::is_same_v<Element, FlatbuffersUnionTag>) {
      // TODO(b/399123660): implement this.
      return Domain<std::optional<bool>>(OptionalOf(ArbitraryImpl<bool>()));
    } else {
      auto inner = OptionalOf(
          ContainerOf<std::vector<Element>>(ArbitraryImpl<Element>()));
      if (!field->optional()) {
        inner.SetWithoutNull();
      }
      return Domain<std::optional<std::vector<Element>>>{inner};
    }
  }

  // Returns the domain for the given field.
  template <typename T>
  auto GetDomainForField(const Field* field) const {
    if constexpr (std::is_same_v<T, FlatbuffersArrayTag>) {
      // TODO(b/399123660): Implement this.
      return Domain<std::optional<bool>>(OptionalOf(ArbitraryImpl<bool>()));
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
      auto inner = OptionalOf(ElementOfImpl<LazyInt>(std::move(values)));
      if (!field->optional()) {
        inner.SetWithoutNull();
      }
      return Domain<std::optional<LazyInt>>{inner};
    } else if constexpr (std::is_same_v<T, FlatbuffersTableTag>) {
      auto table_object = schema_->objects()->Get(field->type()->index());
      auto inner =
          OptionalOf(FlatbuffersTableUntypedDomainImpl<FlatbuffersToolbox>{
              schema_, table_object});
      if (!field->optional()) {
        inner.SetWithoutNull();
      }
      return Domain<std::optional<const Table*>>{inner};
    } else if constexpr (std::is_same_v<T, FlatbuffersStructTag>) {
      // TODO(b/399123660): Implement this.
      return Domain<std::optional<bool>>(OptionalOf(ArbitraryImpl<bool>()));
    } else if constexpr (std::is_same_v<T, FlatbuffersUnionTag>) {
      // TODO(b/399123660): Implement this.
      return Domain<std::optional<bool>>(OptionalOf(ArbitraryImpl<bool>()));
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

  uint32_t BuildTable(const corpus_type& value, Builder& builder) const {
    // Add all the out of line fields to the builder.
    std::unordered_map<FieldIdT, UOffsetT> offsets;
    for (const auto& [id, field_corpus] : value) {
      const Field* field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      VisitFlatbuffersField(
          schema_, field,
          TableFieldBuilderVisitor{*this, builder, offsets, field_corpus});
    }
    // Build the table with the out of line fields offsets and inline fields.
    uint32_t table_start = builder.StartTable();
    for (const auto& [id, field_corpus] : value) {
      const Field* field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      VisitFlatbuffersField(
          schema_, field,
          TableBuilderVisitor{*this, builder, offsets, field_corpus});
    }
    return builder.EndTable(table_start);
  }

 private:
  const Schema* schema_;
  const Object* table_object_;
  mutable absl::Mutex mutex_;
  mutable absl::flat_hash_map<FieldIdT, CopyableAny> domains_
      ABSL_GUARDED_BY(mutex_);

  const Field* GetFieldById(FieldIdT id) const {
    const auto it =
        absl::c_find_if(*table_object_->fields(),
                        [id](const auto* field) { return field->id() == id; });
    return it != table_object_->fields()->end() ? *it : nullptr;
  }

  bool IsScalarType(BaseType base_type) const {
    switch (base_type) {
      case BaseType::Bool:
      case BaseType::Byte:
      case BaseType::Short:
      case BaseType::Int:
      case BaseType::Long:
      case BaseType::UByte:
      case BaseType::UShort:
      case BaseType::UInt:
      case BaseType::ULong:
      case BaseType::Float:
      case BaseType::Double:
        return true;
      default:
        return false;
    }
  }

  struct SerializeVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    const GenericDomainCorpusType& corpus_value;
    IRObject& out;

    template <typename T>
    void Visit(const Field* field) {
      out = self.GetSubDomain<T>(field).SerializeCorpus(corpus_value);
    }
  };

  struct FromValueVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    value_type value;
    corpus_type& out;

    template <typename T>
    bool Visit(const Field* field) const {
      [[maybe_unused]]
      BaseType base_type = field->type()->base_type();
      auto& domain = self.GetSubDomain<T>(field);
      value_type_t<std::decay_t<decltype(domain)>> inner_value;

      if constexpr (is_flatbuffers_enum_tag_v<T>) {
        assert(base_type >= BaseType::Byte && base_type <= BaseType::ULong);
        if (field->optional() && !value->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value =
              std::make_optional(value->template GetField<typename T::type>(
                  field->offset(), field->default_integer()));
        }
      } else if constexpr (std::is_integral_v<T>) {
        assert(base_type >= BaseType::Bool && base_type <= BaseType::ULong);
        if (field->optional() && !value->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::make_optional(value->template GetField<T>(
              field->offset(), field->default_integer()));
        }
      } else if constexpr (std::is_floating_point_v<T>) {
        assert(base_type >= BaseType::Float && base_type <= BaseType::Double);
        if (field->optional() && !value->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::make_optional(value->template GetField<T>(
              field->offset(), field->default_real()));
        }
      } else if constexpr (std::is_same_v<T, std::string>) {
        assert(base_type == BaseType::String);
        if (!value->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::make_optional(
              value->template GetPointer<String*>(field->offset())->str());
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersTableTag>) {
        auto sub_object = self.schema_->objects()->Get(field->type()->index());
        assert(base_type == BaseType::Obj && !sub_object->is_struct());
        inner_value = value->template GetPointer<const Table*>(field->offset());
      } else if constexpr (is_flatbuffers_vector_tag_v<T>) {
        assert(base_type == BaseType::Vector ||
               base_type == BaseType::Vector64);
        if (!value->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          using ElementType = typename T::value_type;
          if constexpr (std::is_integral_v<ElementType> ||
                        std::is_floating_point_v<ElementType>) {
            auto vec = value->template GetPointer<Vector<ElementType>*>(
                field->offset());
            inner_value = std::make_optional(std::vector<ElementType>());
            inner_value->reserve(vec->size());
            for (auto i = 0; i < vec->size(); ++i) {
              inner_value->push_back(vec->Get(i));
            }
          } else if constexpr (is_flatbuffers_enum_tag_v<ElementType>) {
            using Underlaying = typename ElementType::type;
            auto vec = value->template GetPointer<Vector<Underlaying>*>(
                field->offset());
            inner_value = std::make_optional(std::vector<Underlaying>());
            inner_value->reserve(vec->size());
            for (auto i = 0; i < vec->size(); ++i) {
              inner_value->push_back(vec->Get(i));
            }
          } else if constexpr (std::is_same_v<ElementType, std::string>) {
            auto vec = value->template GetPointer<Vector<Offset<String>>*>(
                field->offset());
            inner_value = std::make_optional(std::vector<std::string>());
            inner_value->reserve(vec->size());
            for (auto i = 0; i < vec->size(); ++i) {
              inner_value->push_back(vec->Get(i)->str());
            }
          } else if constexpr (std::is_same_v<ElementType,
                                              FlatbuffersTableTag>) {
            auto vec = value->template GetPointer<Vector<Offset<Table>>*>(
                field->offset());
            inner_value = std::make_optional(std::vector<const Table*>());
            inner_value->reserve(vec->size());
            for (auto i = 0; i < vec->size(); ++i) {
              inner_value->push_back(vec->Get(i));
            }
          } else {
            return false;
          }
        }
      } else {
        return false;
      }

      auto inner = domain.FromValue(inner_value);
      if (!inner) {
        return false;
      }
      out[field->id()] = *std::move(inner);
      return true;
    };
  };

  struct TableFieldBuilderVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    Builder& builder;
    std::unordered_map<FieldIdT, UOffsetT>& offsets;
    const typename corpus_type::value_type::second_type& corpus_value;

    template <typename T>
    bool Visit(const Field* field) const {
      if constexpr (std::is_same_v<T, std::string>) {
        auto& domain = self.GetSubDomain<T>(field);
        auto user_value = domain.GetValue(corpus_value);
        if (user_value.has_value()) {
          auto offset =
              builder.CreateString(user_value->data(), user_value->size()).o;
          offsets.insert({field->id(), offset});
        }
      } else if constexpr (std::is_same_v<T, FlatbuffersTableTag>) {
        FlatbuffersTableUntypedDomainImpl<FlatbuffersToolbox> inner_domain(
            self.schema_, self.schema_->objects()->Get(field->type()->index()));
        auto opt_corpus = corpus_value.template GetAs<
            std::variant<std::monostate, fuzztest::GenericDomainCorpusType>>();
        if (std::holds_alternative<fuzztest::GenericDomainCorpusType>(
                opt_corpus)) {
          auto inner_corpus =
              std::get<fuzztest::GenericDomainCorpusType>(opt_corpus)
                  .template GetAs<corpus_type>();
          auto offset = inner_domain.BuildTable(inner_corpus, builder);
          offsets.insert({field->id(), offset});
        }
      } else if constexpr (is_flatbuffers_vector_tag_v<T>) {
        return VisitVector<typename T::value_type>(field,
                                                   self.GetSubDomain<T>(field));
      }
      return false;
    }

   private:
    template <typename Element, typename Domain>
    bool VisitVector(const Field* field, const Domain& domain) const {
      if constexpr (std::is_integral_v<Element> ||
                    std::is_floating_point_v<Element>) {
        auto value = domain.GetValue(corpus_value);
        if (!value) {
          return true;
        }
        offsets.insert({field->id(), builder.CreateVector(*value).o});
        return true;
      } else if constexpr (is_flatbuffers_enum_tag_v<Element>) {
        auto value = domain.GetValue(corpus_value);
        if (!value) {
          return true;
        }
        offsets.insert({field->id(), builder.CreateVector(*value).o});
        return true;
      }
      if constexpr (std::is_same_v<Element, FlatbuffersTableTag>) {
        FlatbuffersTableUntypedDomainImpl<FlatbuffersToolbox> domain(
            self.schema_, self.schema_->objects()->Get(field->type()->index()));
        auto opt_corpus = corpus_value.template GetAs<
            std::variant<std::monostate, fuzztest::GenericDomainCorpusType>>();
        if (std::holds_alternative<std::monostate>(opt_corpus)) {
          return true;
        }
        auto container_corpus =
            std::get<fuzztest::GenericDomainCorpusType>(opt_corpus)
                .template GetAs<std::list<corpus_type>>();
        std::vector<Offset<Table>> vec_offsets;
        for (auto& inner_corpus : container_corpus) {
          auto offset = domain.BuildTable(inner_corpus, builder);
          vec_offsets.push_back(offset);
        }
        offsets.insert({field->id(), builder.CreateVector(vec_offsets).o});
        return true;
      } else if constexpr (std::is_same_v<Element, std::string>) {
        auto value = domain.GetValue(corpus_value);
        if (!value) {
          return true;
        }
        std::vector<Offset<String>> vec_offsets;
        for (const auto& str : *value) {
          auto offset = builder.CreateString(str);
          vec_offsets.push_back(offset);
        }
        offsets.insert({field->id(), builder.CreateVector(vec_offsets).o});
        return true;
      }
      return false;
    }
  };

  struct TableBuilderVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    Builder& builder;
    std::unordered_map<FieldIdT, UOffsetT>& offsets;
    const typename corpus_type::value_type::second_type& corpus_value;

    template <typename T>
    bool Visit(const Field* field) const {
      auto size = FlatbuffersToolbox::GetTypeSize(field->type()->base_type());
      if constexpr (std::is_integral_v<T> || std::is_floating_point_v<T> ||
                    is_flatbuffers_enum_tag_v<T>) {
        auto& domain = self.GetSubDomain<T>(field);
        auto v = domain.GetValue(corpus_value);
        if (!v) {
          return true;
        }
        builder.Align(size);
        builder.PushBytes(reinterpret_cast<const uint8_t*>(&v), size);
        builder.TrackField(field->offset(), builder.GetSize());
        return true;
      } else if constexpr (std::is_same_v<T, std::string> ||
                           is_flatbuffers_vector_tag_v<T>) {
        if (auto it = offsets.find(field->id()); it != offsets.end()) {
          builder.AddOffset(field->offset(), Offset<void>(it->second));
        }
        return true;
      } else if constexpr (std::is_same_v<T, FlatbuffersTableTag>) {
        if (auto it = offsets.find(field->id()); it != offsets.end()) {
          builder.AddOffset(field->offset(), Offset<Table>(it->second));
        }
        return true;
      }
      return false;
    }
  };

  struct ParseVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    const IRObject& obj;
    std::optional<GenericDomainCorpusType>& out;

    template <typename T>
    void Visit(const Field* field) {
      out = self.GetSubDomain<T>(field).ParseCorpus(obj);
    }
  };

  struct ValidateVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    const GenericDomainCorpusType* corpus_value;
    absl::Status& out;

    template <typename T>
    void Visit(const Field* field) {
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
    FlatbuffersTableUntypedDomainImpl& self;
    absl::BitGenRef prng;
    corpus_type& val;

    template <typename T>
    void Visit(const Field* field) {
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
    bool Visit(const Field* field) {
      auto& domain = self.GetSubDomain<T>(field);
      if (auto it = val.find(field->id()); it != val.end()) {
        domain.Mutate(it->second, prng, metadata, only_shrink);
      } else if (!only_shrink) {
        val[field->id()] = domain.Init(prng);
      }
      return true;
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
          first = false;
        }
        const Field* field = self.GetFieldById(id);
        if (field == nullptr) {
          absl::Format(out, "<unknown field: %d>", id);
        } else {
          VisitFlatbuffersField(self.schema_, field,
                                PrinterVisitor{self, field_corpus, out, mode});
        }
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
    bool Visit(const Field* field) const {
      auto& domain = self.GetSubDomain<T>(field);
      absl::Format(out, "%s: ", field->name()->str());
      domain_implementor::PrintValue(domain, val, out, mode);
      return true;
    }
  };
};

// Domain implementation for flatbuffers generated table classes.
template <typename T, typename FlatbuffersToolbox,
          typename UntypedImpl =
              FlatbuffersTableUntypedDomainImpl<FlatbuffersToolbox>>
class FlatbuffersTableDomainImpl
    : public domain_implementor::DomainBase<
          FlatbuffersTableDomainImpl<T, FlatbuffersToolbox>, const T*,
          std::pair<corpus_type_t<UntypedImpl>, std::vector<uint8_t>>> {
 public:
  static_assert(
      Requires<const T*>([](auto) -> decltype(T::BinarySchema::data()) {}),
      "The flatbuffers generated class must be generated with the "
      "`--bfbs-gen-embed` flag.");
  static_assert(
      Requires<const T*>([](auto) -> decltype(T::GetFullyQualifiedName()) {}),
      "The flatbuffers generated class must be generated with the "
      "`--gen-name-strings` flag.");
  static_assert(is_valid_toolbox_t<FlatbuffersToolbox>());

  using typename FlatbuffersTableDomainImpl::DomainBase::corpus_type;
  using typename FlatbuffersTableDomainImpl::DomainBase::value_type;
  using Builder = typename FlatbuffersToolbox::builder_type;
  using Schema = typename FlatbuffersToolbox::schema_type;
  using Verifier = typename FlatbuffersToolbox::verifier_type;
  using Table = typename FlatbuffersToolbox::table_type;
  template <typename OffsetT = void>
  using Offset = typename FlatbuffersToolbox::template offset_type<OffsetT>;
  using Object = get_object_t<Schema>;

  FlatbuffersTableDomainImpl() {
    Verifier verifier(T::BinarySchema::data(), T::BinarySchema::size());
    FUZZTEST_INTERNAL_CHECK(FlatbuffersToolbox::VerifySchemaBuffer(verifier),
                            "Invalid schema for flatbuffers table.");
    auto schema =
        FlatbuffersToolbox::template GetRoot<Schema>(T::BinarySchema::data());
    auto table_object =
        schema->objects()->LookupByKey(T::GetFullyQualifiedName());
    inner_ = FlatbuffersTableUntypedDomainImpl<FlatbuffersToolbox>{
        schema, table_object};
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
    auto val = inner_->Init(prng);
    auto offset = inner_->BuildTable(val, builder_);
    builder_.Finish(Offset<Table>(offset));
    auto buffer =
        std::vector<uint8_t>(builder_.GetBufferPointer(),
                             builder_.GetBufferPointer() + builder_.GetSize());
    builder_.Clear();
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
    inner_->Mutate(val.first, prng, metadata, only_shrink);
    val.second = BuildBuffer(val.first);
  }

  // Returns the parsed corpus value.
  value_type GetValue(const corpus_type& value) const {
    return FlatbuffersToolbox::template GetRoot<T>(value.second.data());
  }

  // Returns the parsed corpus value.
  std::optional<corpus_type> FromValue(const value_type& value) const {
    auto val = inner_->FromValue((const Table*)value);
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
  std::optional<UntypedImpl> inner_;
  mutable Builder builder_;

  struct Printer {
    const FlatbuffersTableUntypedDomainImpl<FlatbuffersToolbox>& inner;

    void PrintCorpusValue(const corpus_type& value,
                          domain_implementor::RawSink out,
                          domain_implementor::PrintMode mode) const {
      inner.GetPrinter().PrintCorpusValue(value.first, out, mode);
    }
  };

  std::vector<uint8_t> BuildBuffer(
      const typename corpus_type::first_type& val) const {
    auto offset = inner_->BuildTable(val, builder_);
    builder_.Finish(Offset<Table>(offset));
    auto buffer =
        std::vector<uint8_t>(builder_.GetBufferPointer(),
                             builder_.GetBufferPointer() + builder_.GetSize());
    builder_.Clear();
    return buffer;
  }
};
}  // namespace fuzztest::internal
#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FLATBUFFERS_DOMAIN_IMPL_H_
