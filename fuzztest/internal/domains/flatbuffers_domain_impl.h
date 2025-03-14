#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FLATBUFFERS_DOMAIN_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FLATBUFFERS_DOMAIN_IMPL_H_

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <functional>
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

// Deduct the `reflection::Object` type from the `reflection::Schema` type.
template <typename Schema>
using get_object_t = remove_pointer_cv_t<typename remove_pointer_cv_t<
    std::invoke_result_t<decltype(&Schema::objects), Schema>>::value_type>;

// Deduct the `reflection::Field` type from the `reflection::Object` type.
template <typename Object>
using get_field_t = remove_pointer_cv_t<typename remove_pointer_cv_t<
    std::invoke_result_t<decltype(&Object::fields), Object>>::value_type>;

// Deduct the `flatbuffers::String` type from the `reflection::Object` type.
template <typename Object>
using get_string_t =
    remove_pointer_cv_t<std::invoke_result_t<decltype(&Object::name), Object>>;

// Deduct the `flatbuffers::Offset` type from the `reflection::Object` type.
template <typename Object>
using get_offset_t =
    ExtractTemplateParameter<0, remove_pointer_cv_t<std::invoke_result_t<
                                    decltype(&Object::fields), Object>>>;

// Deduct the `reflection::BaseType` type from the `reflection::Field` type.
template <typename Field>
struct get_base_type {
 private:
  using type =
      remove_pointer_cv_t<std::invoke_result_t<decltype(&Field::type), Field>>;

 public:
  using base_type = remove_pointer_cv_t<
      std::invoke_result_t<decltype(&type::base_type), type>>;
};
// Deduct the `reflection::BaseType` type from the `reflection::Field` type.
template <typename Field>
using get_base_type_t = typename get_base_type<Field>::base_type;

// Deduct the `flatbuffers::DetachedBuffer` type from the
// `flatbuffers::FlatBufferBuilder` type.
template <typename Builder>
using get_detached_buffer_t = remove_pointer_cv_t<
    std::invoke_result_t<decltype(&Builder::Release), Builder>>;

struct FlatbuffersArrayTag;
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

struct FlatbuffersTableTag;
struct FlatbuffersStructTag;
struct FlatbuffersUnionTag;
struct FlatbuffersVectorTag;

// Callback function that builds a flatbuffers table from a corpus value.
template <typename CorpusType, typename Builder>
using BuildCallback = std::function<uint32_t(CorpusType&, Builder&)>;

// Dynamic to static dispatch visitor pattern.
template <typename Schema, typename Field, typename Visitor>
auto VisitFlatbuffersField(const Schema* schema, const Field* field,
                           Visitor visitor) {
  using BaseType = get_base_type_t<Field>;

  switch (field->type()->base_type()) {
    case BaseType::Bool:
      visitor.template Visit<bool>(field);
      break;
    case BaseType::Byte:
      if (field->type()->index() >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<int8_t>>(field);
      } else {
        visitor.template Visit<int8_t>(field);
      }
      break;
    case BaseType::Short:
      if (field->type()->index() >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<int16_t>>(field);
      } else {
        visitor.template Visit<int16_t>(field);
      }
      break;
    case BaseType::Int:
      if (field->type()->index() >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<int32_t>>(field);
      } else {
        visitor.template Visit<int32_t>(field);
      }
      break;
    case BaseType::Long:
      if (field->type()->index() >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<int64_t>>(field);
      } else {
        visitor.template Visit<int64_t>(field);
      }
      break;
    case BaseType::UByte:
      if (field->type()->index() >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<uint8_t>>(field);
      } else {
        visitor.template Visit<uint8_t>(field);
      }
      break;
    case BaseType::UShort:
      if (field->type()->index() >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<uint16_t>>(field);
      } else {
        visitor.template Visit<uint16_t>(field);
      }
      break;
    case BaseType::UInt:
      if (field->type()->index() >= 0) {
        visitor.template Visit<FlatbuffersEnumTag<uint32_t>>(field);
      } else {
        visitor.template Visit<uint32_t>(field);
      }
      break;
    case BaseType::ULong:
      if (field->type()->index() >= 0) {
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
    case BaseType::Vector64:
      visitor.template Visit<FlatbuffersVectorTag>(field);
      break;
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
constexpr bool is_valid_toolbox_t =
    Requires<FlatbuffersToolbox>([](auto toolbox) ->
                                 typename FlatbuffersToolbox::table_type {}) &&
    Requires<FlatbuffersToolbox>([](auto toolbox) ->
                                 typename FlatbuffersToolbox::schema_type {}) &&
    Requires<FlatbuffersToolbox>(
        [](auto toolbox) -> typename FlatbuffersToolbox::builder_type {}) &&
    Requires<FlatbuffersToolbox>(
        [](auto toolbox)
            -> decltype(toolbox.GetTypeSize(
                std::declval<typename FlatbuffersToolbox::base_type>())) {}) &&
    Requires<FlatbuffersToolbox>(
        [](auto toolbox)
            -> decltype(toolbox.template GetRoot<
                        typename FlatbuffersToolbox::table_type>(
                std::declval<
                    const typename FlatbuffersToolbox::table_type*>())) {}) &&
    Requires<FlatbuffersToolbox>(
        [](auto toolbox)
            -> decltype(toolbox.VerifySchemaBuffer(
                std::declval<typename FlatbuffersToolbox::verifier_type&>())) {
        });

// Untyped domain implementation for flatbuffers generated table classes.
template <typename FlatbuffersToolbox>
class FlatbuffersTableUntypedDomainImpl
    : public domain_implementor::DomainBase<
          FlatbuffersTableUntypedDomainImpl<FlatbuffersToolbox>,
          const typename FlatbuffersToolbox::table_type*,
          absl::flat_hash_map<uint16_t, GenericDomainCorpusType>> {
 public:
  static_assert(is_valid_toolbox_t<FlatbuffersToolbox>);
  using typename FlatbuffersTableUntypedDomainImpl::DomainBase::corpus_type;
  using typename FlatbuffersTableUntypedDomainImpl::DomainBase::value_type;
  using Builder = typename FlatbuffersToolbox::builder_type;
  using Schema = typename FlatbuffersToolbox::schema_type;
  using Table = typename FlatbuffersToolbox::table_type;
  using Object = get_object_t<Schema>;
  using Field = get_field_t<Object>;
  using String = get_string_t<Object>;
  using Offset = get_offset_t<Object>;
  using BaseType = get_base_type_t<Field>;

  explicit FlatbuffersTableUntypedDomainImpl(
      const Schema* schema, const Object* table_object,
      std::optional<std::function<void(BuildCallback<corpus_type, Builder>)>>
          register_build_callback = std::nullopt)
      : schema_(schema),
        table_object_(table_object),
        register_build_callback_(register_build_callback) {
    if (register_build_callback_.has_value()) {
      (*register_build_callback_)([this](corpus_type& value, Builder& builder) {
        return BuildTable(value, builder);
      });
    }
  }

  FlatbuffersTableUntypedDomainImpl(
      const FlatbuffersTableUntypedDomainImpl& other)
      : schema_(other.schema_),
        table_object_(other.table_object_),
        register_build_callback_(other.register_build_callback_) {
    absl::MutexLock l(&other.mutex_);
    domains_ = other.domains_;
    build_callbacks_ = other.build_callbacks_;
    if (register_build_callback_.has_value()) {
      (*register_build_callback_)([this](corpus_type& value, Builder& builder) {
        return BuildTable(value, builder);
      });
    }
  };

  FlatbuffersTableUntypedDomainImpl& operator=(
      const FlatbuffersTableUntypedDomainImpl& other) {
    if (this != &other) {
      schema_ = other.schema_;
      table_object_ = other.table_object_;
      register_build_callback_ = other.register_build_callback_;
      absl::MutexLock l(&other.mutex_);
      domains_ = other.domains_;
      build_callbacks_ = other.build_callbacks_;
      if (register_build_callback_.has_value()) {
        (*register_build_callback_)(
            [this](corpus_type& value, Builder& builder) {
              return BuildTable(value, builder);
            });
      }
    }
    return *this;
  }

  FlatbuffersTableUntypedDomainImpl(FlatbuffersTableUntypedDomainImpl&& other)
      : schema_(other.schema_),
        table_object_(other.table_object_),
        register_build_callback_(std::move(other.register_build_callback_)) {
    absl::MutexLock l(&other.mutex_);
    domains_ = std::move(other.domains_);
    build_callbacks_ = std::move(other.build_callbacks_);
    if (register_build_callback_.has_value()) {
      (*register_build_callback_)([this](corpus_type& value, Builder& builder) {
        return BuildTable(value, builder);
      });
    }
  }

  FlatbuffersTableUntypedDomainImpl& operator=(
      FlatbuffersTableUntypedDomainImpl&& other) {
    if (this != &other) {
      schema_ = other.schema_;
      table_object_ = other.table_object_;
      register_build_callback_ = std::move(other.register_build_callback_);
      absl::MutexLock l(&other.mutex_);
      domains_ = std::move(other.domains_);
      build_callbacks_ = std::move(other.build_callbacks_);
      if (register_build_callback_.has_value()) {
        (*register_build_callback_)(
            [this](corpus_type& value, Builder& builder) {
              return BuildTable(value, builder);
            });
      }
    }
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
    uint64_t total_weight = CountNumberOfFields(val);
    uint64_t selected_weight =
        absl::Uniform(absl::IntervalClosedClosed, prng, 0ul, total_weight - 1);

    MutateSelectedField(val, prng, metadata, only_shrink, selected_weight);
  }

  // Counts the number of fields that can be mutated.
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
      }
    }
    return total_weight;
  }

  // Mutates the selected field.
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

      if (field->type()->base_type() == BaseType::Obj) {
        auto sub_object = schema_->objects()->Get(field->type()->index());
        if (!sub_object->is_struct()) {
          field_counter +=
              GetSubDomain<FlatbuffersTableTag>(field).MutateSelectedField(
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

  auto GetPrinter() const {
    absl::MutexLock l(&mutex_);
    return Printer{*this};
  }

  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const {
    for (auto& [id, data] : corpus_value) {
      const Field* field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      auto field_value = corpus_value.find(field->id());
      const GenericDomainCorpusType* inner_corpus_value =
          (field_value != corpus_value.end()) ? &field_value->second : nullptr;
      absl::Status result;
      VisitFlatbuffersField(schema_, field,
                            ValidateVisitor{*this, inner_corpus_value, result});
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
    for (size_t i = 0; i < table_object_->fields()->size(); ++i) {
      const auto* field = table_object_->fields()->Get(i);
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
      auto id = (*pair_subs)[0].GetScalar<uint16_t>();
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
    for (auto& [id, field_corpus] : value) {
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
      auto register_build_callback =
          [this, id = field->id()](
              std::function<uint32_t(corpus_type&, Builder&)> callback) {
            build_callbacks_.insert_or_assign(id, std::move(callback));
          };
      auto inner =
          OptionalOf(FlatbuffersTableUntypedDomainImpl<FlatbuffersToolbox>{
              schema_, table_object, register_build_callback});
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

  uint32_t BuildTable(corpus_type& value, Builder& builder) const {
    // Add all the fields to the builder.
    std::unordered_map<uint16_t, uint32_t> offsets;
    for (auto& [id, data] : value) {
      const Field* field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      switch (field->type()->base_type()) {
        case BaseType::String: {
          auto& domain = GetSubDomain<std::string>(field);
          auto user_value = domain.GetValue(data);
          if (user_value.has_value()) {
            uint32_t offset =
                builder.CreateString(user_value->data(), user_value->size()).o;
            offsets.insert({id, offset});
          }
          break;
        }
        case BaseType::Obj: {
          auto& subobjectdef = *schema_->objects()->Get(field->type()->index());
          if (!subobjectdef.is_struct()) {
            auto it = build_callbacks_.find(id);
            if (it != build_callbacks_.end()) {
              auto& callback = it->second;
              auto opt_corpus = data.template GetAs<std::variant<
                  std::monostate, fuzztest::GenericDomainCorpusType>>();
              if (std::holds_alternative<fuzztest::GenericDomainCorpusType>(
                      opt_corpus)) {
                auto inner_corpus =
                    std::get<fuzztest::GenericDomainCorpusType>(opt_corpus)
                        .template GetAs<corpus_type>();
                auto offset = callback(inner_corpus, builder);
                offsets.insert({id, offset});
              }
            }
          } else {
            // TODO (b/399123660): Implement for structs.
          }
          break;
        }
        case BaseType::Union:
          // TODO(b/399123660): Implement this.
          break;
        case BaseType::Vector:
          // TODO(b/399123660): Implement this.
          break;
        case BaseType::Array:
          // TODO(b/399123660): Implement this.
          break;
        default:  // Scalars.
          break;
      }
    }
    // Build the table.
    uint32_t table_start = builder.StartTable();
    for (auto& [id, data] : value) {
      const Field* field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      switch (field->type()->base_type()) {
        case BaseType::Obj: {
          auto& subobjectdef = *schema_->objects()->Get(field->type()->index());
          if (!subobjectdef.is_struct() && offsets.find(id) != offsets.end()) {
            builder.AddOffset(field->offset(), Offset(offsets[id]));
          }
          break;
        }
        case BaseType::Union:
        case BaseType::String:
        case BaseType::Vector:
          if (offsets.find(id) != offsets.end()) {
            builder.AddOffset(field->offset(), Offset(offsets[id]));
          }
          break;
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
          VisitFlatbuffersField(schema_, field,
                                ScalarBuilderVisitor{*this, builder, data});
          break;
        default:
          break;
      }
    }
    return builder.EndTable(table_start);
  }

 private:
  const Schema* schema_;
  const Object* table_object_;
  mutable absl::Mutex mutex_;
  mutable absl::flat_hash_map<uint16_t, CopyableAny> domains_
      ABSL_GUARDED_BY(mutex_);
  std::optional<std::function<void(BuildCallback<corpus_type, Builder>)>>
      register_build_callback_;
  mutable absl::flat_hash_map<uint16_t,
                              std::function<uint32_t(corpus_type&, Builder&)>>
      build_callbacks_;

  const Field* GetFieldById(uint16_t id) const {
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

  bool IsTypeSupported(BaseType base_type) const {
    return IsScalarType(base_type) || base_type == BaseType::String;
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
      }

      auto inner = domain.FromValue(inner_value);
      if (!inner) {
        return false;
      }
      out[field->id()] = *std::move(inner);
      return true;
    };
  };

  struct ScalarBuilderVisitor {
    const FlatbuffersTableUntypedDomainImpl& self;
    Builder& builder;
    const typename corpus_type::value_type::second_type& value;

    template <typename T>
    bool Visit(const Field* field) const {
      BaseType base_type = field->type()->base_type();
      if (!self.IsScalarType(base_type)) {
        return false;
      }
      auto& domain = self.GetSubDomain<T>(field);
      if constexpr (is_flatbuffers_enum_tag_v<T>) {
        return BuildScalar<typename T::type>(field, domain);
      } else if constexpr (std::is_integral_v<T> ||
                           std::is_floating_point_v<T>) {
        return BuildScalar<T>(field, domain);
      }
      return false;
    }

   private:
    template <typename T, typename Inner>
    bool BuildScalar(const Field* field, Inner domain) const {
      auto size = FlatbuffersToolbox::GetTypeSize(field->type()->base_type());
      auto v = domain.GetValue(value);
      if (!v) {
        return false;
      }
      builder.Align(size);
      builder.PushBytes(reinterpret_cast<const uint8_t*>(&v), size);
      builder.TrackField(field->offset(), builder.GetSize());
      return true;
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
      for (auto& [id, inner_value] : value) {
        if (!first) {
          absl::Format(out, ", ");
          first = false;
        }
        const Field* field = self.GetFieldById(id);
        if (field == nullptr) {
          absl::Format(out, "<unknown field: %d>", id);
        } else {
          VisitFlatbuffersField(self.schema_, field,
                                PrinterVisitor{self, inner_value, out, mode});
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
  static_assert(is_valid_toolbox_t<FlatbuffersToolbox>);

  using typename FlatbuffersTableDomainImpl::DomainBase::corpus_type;
  using typename FlatbuffersTableDomainImpl::DomainBase::value_type;
  using Builder = typename FlatbuffersToolbox::builder_type;
  using Schema = typename FlatbuffersToolbox::schema_type;
  using Verifier = typename FlatbuffersToolbox::verifier_type;
  using Table = typename FlatbuffersToolbox::table_type;
  using Object = get_object_t<Schema>;
  using Offset = get_offset_t<Object>;

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

  // Initializes the table with random values.
  corpus_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    auto val = inner_->Init(prng);
    auto offset = inner_->BuildTable(val, builder_);
    builder_.Finish(Offset(offset));
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
    auto offset = inner_->BuildTable(val.first, builder_);
    builder_.Finish(Offset(offset));
    auto buffer =
        std::vector<uint8_t>(builder_.GetBufferPointer(),
                             builder_.GetBufferPointer() + builder_.GetSize());
    builder_.Clear();
    val.second = std::move(buffer);
  }

  // Returns the parsed corpus value.
  value_type GetValue(const corpus_type& value) const {
    return FlatbuffersToolbox::template GetRoot<T>(value.second.data());
  }

  // Returns the parsed corpus value.
  std::optional<corpus_type> FromValue(const value_type& value) const {
    auto val = inner_->FromValue((const Table*)value);
    if (!val.has_value()) return std::nullopt;
    auto offset = inner_->BuildTable(val.value(), builder_);
    builder_.Finish(Offset(offset));
    auto buffer =
        std::vector<uint8_t>(builder_.GetBufferPointer(),
                             builder_.GetBufferPointer() + builder_.GetSize());
    builder_.Clear();
    return std::make_optional(std::make_pair(val.value(), std::move(buffer)));
  }

  // Returns the printer for the table.
  auto GetPrinter() const { return Printer{*inner_}; }

  // Returns the parsed corpus value.
  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    auto val = inner_->ParseCorpus(obj);
    if (!val.has_value()) return std::nullopt;
    auto offset = inner_->BuildTable(val.value(), builder_);
    builder_.Finish(Offset(offset));
    auto buffer =
        std::vector<uint8_t>(builder_.GetBufferPointer(),
                             builder_.GetBufferPointer() + builder_.GetSize());
    builder_.Clear();
    return std::make_optional(std::make_pair(val.value(), std::move(buffer)));
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
};
}  // namespace fuzztest::internal
#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FLATBUFFERS_DOMAIN_IMPL_H_
