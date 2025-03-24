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

// Deduct the `flatbuffers::FlatbufferBuilder` type from the Generated type.
template <typename Generated>
using get_builder_t = std::decay_t<decltype(Generated::Builder::fbb_)>;

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

struct FlatbuffersObjTag;
struct FlatbuffersUnionTag;
struct FlatbuffersVectorTag;

// Dynamic to static dispatch visitor pattern.
template <typename Field, typename Visitor>
auto VisitFlatbuffersField(const Field* field, Visitor visitor) {
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
    case BaseType::Obj:
      visitor.template Visit<FlatbuffersObjTag>(field);
      break;
    case BaseType::Union:
      visitor.template Visit<FlatbuffersUnionTag>(field);
      break;
    default:
      FUZZTEST_INTERNAL_CHECK(false, "Unsupported base type");
  }
}

// Domain implementation for flatbuffers generated table classes.
// It requires the corresponding reflection schema to be passed in the
// constructor.
// The Generated table class is the class that is generated by the flatbuffers
// compiler, and is used to access the fields of the table.
// Additionally, a few types are passed from the flatbuffers library to avoid
// including it:
// - Table: the flatbuffers::Table type, which is the base class for all tables.
// - Schema: the flatbuffers::reflection::Schema type, which is the reflection
// schema of the table.
template <typename Generated, typename Table, typename Schema,
          typename Verifier>
class FlatbuffersTableImpl
    : public domain_implementor::DomainBase<
          FlatbuffersTableImpl<Generated, Table, Schema, Verifier>,
          const Generated*,
          std::pair<absl::flat_hash_map<uint16_t, GenericDomainCorpusType>,
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
  using Builder = get_builder_t<Generated>;
  using Object = get_object_t<Schema>;
  using Field = get_field_t<Object>;
  using String = get_string_t<Object>;
  using Offset = get_offset_t<Object>;
  using BaseType = get_base_type_t<Field>;
  using TypeSizeGetter = std::function<size_t(BaseType)>;
  using RootGetter = std::function<const Generated*(const void*)>;
  using SchemaGetter = std::function<const Schema*(const void*)>;
  using SchemaBufferVerifier = std::function<bool(Verifier& verifier)>;

  // Constructor.
  // The get_schema function is reflection::GetSchema.
  // The verify_schema_buffer function is reflection::VerifySchemaBuffer.
  // The get_type_size function is reflection::GetTypeSize.
  // The get_root function is flatbuffers::GetRoot<Generated>.
  explicit FlatbuffersTableImpl(SchemaGetter get_schema,
                                SchemaBufferVerifier verify_schema_buffer,
                                TypeSizeGetter get_type_size,
                                RootGetter get_root)
      : get_type_size_(get_type_size), get_root_(get_root) {
    Verifier verifier(Generated::BinarySchema::data(),
                      Generated::BinarySchema::size());
    FUZZTEST_INTERNAL_CHECK(verify_schema_buffer(verifier),
                            "Invalid schema for flatbuffers table.");
    schema_ = get_schema(Generated::BinarySchema::data());
    table_object_ =
        schema_->objects()->LookupByKey(Generated::GetFullyQualifiedName());
  }

  FlatbuffersTableImpl(const FlatbuffersTableImpl& other)
      : schema_(other.schema_),
        table_object_(other.table_object_),
        get_type_size_(other.get_type_size_),
        get_root_(other.get_root_) {
    absl::MutexLock l(&other.mutex_);
    domains_ = other.domains_;
  };

  FlatbuffersTableImpl& operator=(const FlatbuffersTableImpl& other) {
    if (this != &other) {
      schema_ = other.schema_;
      table_object_ = other.table_object_;
      absl::MutexLock l(&other.mutex_);
      domains_ = other.domains_;
      get_type_size_ = other.get_type_size_;
      get_root_ = other.get_root_;
    }
    return *this;
  }

  FlatbuffersTableImpl(FlatbuffersTableImpl&& other)
      : schema_(other.schema_),
        table_object_(other.table_object_),
        get_type_size_(std::move(other.get_type_size_)),
        get_root_(std::move(other.get_root_)) {
    absl::MutexLock l(&other.mutex_);
    domains_ = std::move(other.domains_);
  }

  FlatbuffersTableImpl& operator=(FlatbuffersTableImpl&& other) {
    if (this != &other) {
      schema_ = other.schema_;
      table_object_ = other.table_object_;
      absl::MutexLock l(&other.mutex_);
      domains_ = std::move(other.domains_);
      get_type_size_ = std::move(other.get_type_size_);
      get_root_ = std::move(other.get_root_);
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
      VisitFlatbuffersField(field, InitializeVisitor{*this, prng, val});
    }
    UpdateCorpusBuffer(val);
    return val;
  }

  // Mutates the corpus value.
  void Mutate(corpus_type& val, absl::BitGenRef prng,
              const domain_implementor::MutationMetadata& metadata,
              bool only_shrink) {
    std::vector<uint16_t> supported_fields;
    for (size_t i = 0; i < table_object_->fields()->size(); ++i) {
      auto field = table_object_->fields()->Get(i);
      if (IsTypeSupported(field->type()->base_type())) {
        supported_fields.push_back(i);
      }
    }
    uint64_t selected_field_index = absl::Uniform(
        absl::IntervalClosedClosed, prng, 0ul, supported_fields.size() - 1);

    MutateSelectedField(val, prng, metadata, only_shrink, selected_field_index);
  }

  // Counts the number of fields that can be mutated.
  uint64_t CountNumberOfFields(corpus_type& val) {
    uint64_t total_weight = 0;
    for (const auto* field : *table_object_->fields()) {
      if (IsTypeSupported(field->type()->base_type())) {
        ++total_weight;
      }
    }
    return total_weight;
  }

  // Mutates the selected field.
  uint64_t MutateSelectedField(
      corpus_type& val, absl::BitGenRef prng,
      const domain_implementor::MutationMetadata& metadata, bool only_shrink,
      uint64_t selected_field_index) {
    const Field* field = table_object_->fields()->Get(selected_field_index);
    VisitFlatbuffersField(
        field, MutateVisitor{*this, prng, metadata, only_shrink, val});
    UpdateCorpusBuffer(val);
    return 1;
  }

  auto GetPrinter() const {
    absl::MutexLock l(&mutex_);
    return Printer{*this};
  }

  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const {
    for (auto& [id, data] : corpus_value.first) {
      const Field* field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      auto field_value = corpus_value.first.find(field->id());
      const GenericDomainCorpusType* inner_corpus_value =
          (field_value != corpus_value.first.end()) ? &field_value->second
                                                    : nullptr;
      absl::Status result;
      VisitFlatbuffersField(field,
                            ValidateVisitor{*this, inner_corpus_value, result});
      if (!result.ok()) return result;
    }
    return absl::OkStatus();
  }

  value_type GetValue(const corpus_type& value) const {
    return get_root_(value.second.data());
  }

  // Converts the table pointer to a corpus value.
  std::optional<corpus_type> FromValue(const value_type& value) const {
    corpus_type ret;
    for (size_t i = 0; i < table_object_->fields()->size(); ++i) {
      const auto* field = table_object_->fields()->Get(i);
      VisitFlatbuffersField(field, FromValueVisitor{*this, value, ret});
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
      auto id = (*pair_subs)[0].GetScalar<uint16_t>();
      if (!id.has_value()) {
        return std::nullopt;
      }
      const Field* field = GetFieldById(id.value());
      if (field == nullptr) {
        return std::nullopt;
      }
      std::optional<GenericDomainCorpusType> inner_parsed;
      VisitFlatbuffersField(field,
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
    for (auto& [id, field_corpus] : value.first) {
      const Field* field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      IRObject& pair = subs.emplace_back();
      auto& pair_subs = pair.MutableSubs();
      pair_subs.reserve(2);
      pair_subs.emplace_back(field->id());
      VisitFlatbuffersField(field, SerializeVisitor{*this, field_corpus,
                                                    pair_subs.emplace_back()});
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
      auto domain = OptionalOf(ArbitraryImpl<T>());
      if (!field->optional()) {
        domain.SetWithoutNull();
      }
      return Domain<std::optional<T>>{domain};
    }
  }

 private:
  const Schema* schema_;
  const Object* table_object_;
  mutable absl::Mutex mutex_;
  mutable absl::flat_hash_map<uint16_t, CopyableAny> domains_
      ABSL_GUARDED_BY(mutex_);
  TypeSizeGetter get_type_size_;
  RootGetter get_root_;

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

  void UpdateCorpusBuffer(corpus_type& value) const {
    // TODO(b/399123660): The builder may come from a parent domain in case this
    // is a nested table.
    Builder builder;

    // Add all the fields to the builder.
    std::unordered_map<uint16_t, uint32_t> offsets;
    for (auto& [id, data] : value.first) {
      const Field* field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      switch (field->type()->base_type()) {
        case BaseType::String: {
          auto domain = GetSubDomain<std::string>(field);
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
            // TODO(b/399123660): Implement this.
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
    for (auto& [id, data] : value.first) {
      const Field* field = GetFieldById(id);
      if (field == nullptr) {
        continue;
      }
      switch (field->type()->base_type()) {
        case BaseType::Obj: {
          auto& subobjectdef = *schema_->objects()->Get(field->type()->index());
          if (subobjectdef.is_struct()) {
            // builder.Align(subobjectdef.minalign());
            // TODO(b/399123660): add the struct fields to the builder
            // (recursively).
            // builder.TrackField(field->offset(), builder.GetSize());
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
          VisitFlatbuffersField(field,
                                ScalarBuilderVisitor{*this, builder, data});
          break;
        default:
          break;
      }
    }
    auto table_offset = builder.EndTable(table_start);
    builder.template Finish<Table>(table_offset, nullptr);

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
    void Visit(const Field* field) {
      out = self.GetSubDomain<T>(field).SerializeCorpus(corpus_value);
    }
  };

  struct FromValueVisitor {
    const FlatbuffersTableImpl& self;
    value_type value;
    corpus_type& out;

    template <typename T>
    bool Visit(const Field* field) const {
      const Table* table = (const Table*)(value);
      [[maybe_unused]]
      BaseType base_type = field->type()->base_type();
      auto& domain = self.GetSubDomain<T>(field);
      value_type_t<std::decay_t<decltype(domain)>> inner_value;

      if constexpr (is_flatbuffers_enum_tag_v<T>) {
        assert(base_type >= BaseType::Byte && base_type <= BaseType::ULong);
        if (field->optional() && !table->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value =
              std::make_optional(table->template GetField<typename T::type>(
                  field->offset(), field->default_integer()));
        }
      } else if constexpr (std::is_integral_v<T>) {
        assert(base_type >= BaseType::Bool && base_type <= BaseType::ULong);
        if (field->optional() && !table->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::make_optional(table->template GetField<T>(
              field->offset(), field->default_integer()));
        }
      } else if constexpr (std::is_floating_point_v<T>) {
        assert(base_type >= BaseType::Float && base_type <= BaseType::Double);
        if (field->optional() && !table->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::make_optional(table->template GetField<T>(
              field->offset(), field->default_real()));
        }
      } else if constexpr (std::is_same_v<T, std::string>) {
        assert(base_type == BaseType::String);
        if (!table->CheckField(field->offset())) {
          inner_value = std::nullopt;
        } else {
          inner_value = std::make_optional(
              table->template GetPointer<String*>(field->offset())->str());
        }
      }

      auto inner = domain.FromValue(inner_value);
      if (!inner) {
        return false;
      }
      out.first[field->id()] = *std::move(inner);
      return true;
    };
  };

  struct ScalarBuilderVisitor {
    const FlatbuffersTableImpl& self;
    Builder& builder;
    const typename corpus_type::first_type::value_type::second_type& value;

    template <typename T>
    bool Visit(const Field* field) const {
      BaseType base_type = field->type()->base_type();
      if (!self.IsScalarType(base_type)) {
        return false;
      }
      auto domain = self.GetSubDomain<T>(field);
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
      auto size = self.get_type_size_(field->type()->base_type());
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
    const FlatbuffersTableImpl& self;
    const IRObject& obj;
    std::optional<GenericDomainCorpusType>& out;

    template <typename T>
    void Visit(const Field* field) {
      out = self.GetSubDomain<T>(field).ParseCorpus(obj);
    }
  };

  struct ValidateVisitor {
    const FlatbuffersTableImpl& self;
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
    FlatbuffersTableImpl& self;
    absl::BitGenRef prng;
    corpus_type& val;

    template <typename T>
    void Visit(const Field* field) {
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
    bool Visit(const Field* field) {
      auto& domain = self.GetSubDomain<T>(field);
      if (auto it = val.first.find(field->id()); it != val.first.end()) {
        domain.Mutate(it->second, prng, metadata, only_shrink);
      } else if (!only_shrink) {
        val.first[field->id()] = domain.Init(prng);
      }
      return true;
    }
  };

  struct Printer {
    const FlatbuffersTableImpl& self;

    void PrintCorpusValue(const corpus_type& value,
                          domain_implementor::RawSink out,
                          domain_implementor::PrintMode mode) const {
      absl::Format(out, "{");
      bool first = true;
      for (auto& [id, inner_value] : value.first) {
        if (!first) {
          absl::Format(out, ", ");
          first = false;
        }
        const Field* field = self.GetFieldById(id);
        if (field == nullptr) {
          absl::Format(out, "<unknown field: %d>", id);
        } else {
          VisitFlatbuffersField(field,
                                PrinterVisitor{self, inner_value, out, mode});
        }
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
    bool Visit(const Field* field) const {
      auto& domain = self.GetSubDomain<T>(field);
      absl::Format(out, "%s: ", field->name()->str());
      domain_implementor::PrintValue(domain, val, out, mode);
      return true;
    }
  };
};
}  // namespace fuzztest::internal
#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FLATBUFFERS_DOMAIN_IMPL_H_
