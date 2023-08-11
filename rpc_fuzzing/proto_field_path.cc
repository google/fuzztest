// Copyright 2023 Google LLC
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

#include "./rpc_fuzzing/proto_field_path.h"

#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "./fuzztest/internal/logging.h"

namespace fuzztest::internal {

bool Contains(const google::protobuf::FieldDescriptor& parent,
              const google::protobuf::FieldDescriptor& child) {
  return parent.message_type() == child.containing_type();
}

bool operator==(const FieldPath& lhs, const FieldPath& rhs) {
  return lhs.field_descriptors_ == rhs.field_descriptors_;
}

bool FieldPath::CanAppend(const google::protobuf::FieldDescriptor& field) const {
  return field_descriptors_.empty() ||
         Contains(*field_descriptors_.back(), field);
}

void FieldPath::AppendField(const google::protobuf::FieldDescriptor& field) {
  FUZZTEST_INTERNAL_CHECK(
      CanAppend(field),
      "The current last field in the path must be a message containing the "
      "appended field.");
  field_descriptors_.push_back(&field);
}

void FieldPath::AppendPath(const FieldPath& other) {
  if (other.field_descriptors_.empty()) {
    return;
  }
  field_descriptors_.reserve(field_descriptors_.size() +
                             other.field_descriptors_.size());
  FUZZTEST_INTERNAL_CHECK(
      CanAppend(*other.GetAllFields()[0]),
      "The current last field in the path must be a message containing the "
      "first field in the other path.");
  field_descriptors_.insert(field_descriptors_.end(),
                            other.field_descriptors_.begin(),
                            other.field_descriptors_.end());
}

std::string FieldPath::ToString() const {
  return absl::StrJoin(
      field_descriptors_, /*separator=*/".",
      [](std::string* result, const google::protobuf::FieldDescriptor* field) {
        absl::StrAppend(result, field->name());
      });
}

FieldPath GetFieldPathWithDescriptor(const google::protobuf::Descriptor& descriptor,
                                     std::string_view field_path_str) {
  std::vector<std::string> parts = absl::StrSplit(field_path_str, '.');
  FUZZTEST_INTERNAL_CHECK(!parts.empty(), "Invalid path string!");

  FieldPath result;
  const google::protobuf::Descriptor* descriptor_ptr = &descriptor;

  for (const std::string& part : parts) {
    const google::protobuf::FieldDescriptor* field =
        descriptor_ptr->FindFieldByName(part);
    FUZZTEST_INTERNAL_CHECK(field != nullptr, "Invalid field name!");
    result.AppendField(*field);
    descriptor_ptr = field->message_type();
  }
  return result;
}

const google::protobuf::Message* FieldPath::GetContainingMessageOfLastField(
    const google::protobuf::Message& message) const {
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(!field_descriptors_.empty(),
                                       "Empty field path!");
  const google::protobuf::Message* parent = &message;
  for (size_t i = 0; i < field_descriptors_.size() - 1; ++i) {
    if (field_descriptors_[i]->is_repeated()) {
      if (parent->GetReflection()->FieldSize(*parent, field_descriptors_[i]) ==
          0) {
        return nullptr;
      }
      parent = &(parent->GetReflection()->GetRepeatedMessage(
          *parent, field_descriptors_[i], 0));
    } else {
      parent = &(
          parent->GetReflection()->GetMessage(*parent, field_descriptors_[i]));
    }
  }
  return parent;
}

google::protobuf::Message* FieldPath::MutableContainingMessageOfLastField(
    google::protobuf::Message& message) const {
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(!field_descriptors_.empty(),
                                       "Empty field path!");
  google::protobuf::Message* parent = &message;
  for (size_t i = 0; i < field_descriptors_.size() - 1; ++i) {
    if (field_descriptors_[i]->is_repeated()) {
      if (parent->GetReflection()->FieldSize(*parent, field_descriptors_[i]) ==
          0) {
        parent->GetReflection()->AddMessage(parent, field_descriptors_[i]);
      }
      parent = parent->GetReflection()->MutableRepeatedMessage(
          parent, field_descriptors_[i], 0);
    } else {
      parent = parent->GetReflection()->MutableMessage(parent,
                                                       field_descriptors_[i]);
    }
  }
  return parent;
}

const google::protobuf::FieldDescriptor& FieldPath::GetLastField() const {
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(!field_descriptors_.empty(),
                                       "Empty field path!");
  return *field_descriptors_.back();
}

const std::vector<const google::protobuf::FieldDescriptor*>& FieldPath::GetAllFields()
    const {
  return field_descriptors_;
}

void CopyField(const FieldPath& from_field, const google::protobuf::Message& from,
               const FieldPath& to_field, google::protobuf::Message& to) {
  const google::protobuf::Message* from_inner_most_message =
      from_field.GetContainingMessageOfLastField(from);
  if (from_inner_most_message == nullptr) {
    return;
  }
  const google::protobuf::FieldDescriptor& from_last_field = from_field.GetLastField();
  google::protobuf::Message* to_inner_most_message =
      to_field.MutableContainingMessageOfLastField(to);
  if (to_inner_most_message == nullptr) {
    return;
  }
  const google::protobuf::FieldDescriptor& to_last_field = to_field.GetLastField();

  const google::protobuf::Reflection* from_refl =
      from_inner_most_message->GetReflection();
  const google::protobuf::Reflection* to_refl = to_inner_most_message->GetReflection();
  FUZZTEST_INTERNAL_CHECK(from_last_field.type() == to_last_field.type(),
                          "Fields of mismatch types cannot be copied!");
  // TODO(changochen): We might make this condition optional.
  FUZZTEST_INTERNAL_CHECK(from_last_field.name() == to_last_field.name(),
                          "Fields of mismatch names cannot be copied!");
  switch (from_last_field.type()) {
#define HANDLE_TYPE(UPPERCASE, CAMEL)                                         \
  case google::protobuf::FieldDescriptor::TYPE_##UPPERCASE:                             \
    if (from_last_field.is_repeated() && to_last_field.is_repeated()) {       \
      to_refl->ClearField(to_inner_most_message, &to_last_field);             \
      for (int i = 0; i < from_refl->FieldSize(*from_inner_most_message,      \
                                               &from_last_field);             \
           ++i) {                                                             \
        to_refl->Add##CAMEL(                                                  \
            to_inner_most_message, &to_last_field,                            \
            from_refl->GetRepeated##CAMEL(*from_inner_most_message,           \
                                          &from_last_field, i));              \
      }                                                                       \
    } else if (from_last_field.is_repeated()) {                               \
      if (from_refl->FieldSize(*from_inner_most_message, &from_last_field) == \
          0) {                                                                \
        to_refl->ClearField(to_inner_most_message, &to_last_field);           \
      } else {                                                                \
        to_refl->Set##CAMEL(                                                  \
            to_inner_most_message, &to_last_field,                            \
            from_refl->GetRepeated##CAMEL(*from_inner_most_message,           \
                                          &from_last_field, 0));              \
      }                                                                       \
    } else if (to_last_field.is_repeated()) {                                 \
      to_refl->ClearField(to_inner_most_message, &to_last_field);             \
      to_refl->Add##CAMEL(                                                    \
          to_inner_most_message, &to_last_field,                              \
          from_refl->Get##CAMEL(*from_inner_most_message, &from_last_field)); \
    } else {                                                                  \
      to_refl->Set##CAMEL(                                                    \
          to_inner_most_message, &to_last_field,                              \
          from_refl->Get##CAMEL(*from_inner_most_message, &from_last_field)); \
    }                                                                         \
    break;

    HANDLE_TYPE(DOUBLE, Double);
    HANDLE_TYPE(FLOAT, Float);
    HANDLE_TYPE(INT64, Int64);
    HANDLE_TYPE(UINT64, UInt64);
    HANDLE_TYPE(INT32, Int32);
    HANDLE_TYPE(FIXED64, UInt64);
    HANDLE_TYPE(FIXED32, UInt32);
    HANDLE_TYPE(BOOL, Bool);
    HANDLE_TYPE(STRING, String);
    HANDLE_TYPE(BYTES, String);
    HANDLE_TYPE(UINT32, UInt32);
    HANDLE_TYPE(ENUM, Enum);
    HANDLE_TYPE(SFIXED64, Int64);
    HANDLE_TYPE(SFIXED32, Int32);
    HANDLE_TYPE(SINT64, Int64);
    HANDLE_TYPE(SINT32, Int32);

#undef HANDLE_TYPE
    case google::protobuf::FieldDescriptor::TYPE_GROUP:
    case google::protobuf::FieldDescriptor::TYPE_MESSAGE:
      if (from_last_field.is_repeated() && to_last_field.is_repeated()) {
        to_refl->ClearField(to_inner_most_message, &to_last_field);
        for (int i = 0; i < from_refl->FieldSize(*from_inner_most_message,
                                                 &from_last_field);
             ++i) {
          to_refl->AddMessage(to_inner_most_message, &to_last_field)
              ->CopyFrom(from_refl->GetRepeatedMessage(*from_inner_most_message,
                                                       &from_last_field, i));
        }
      } else if (from_last_field.is_repeated()) {
        if (from_refl->FieldSize(*from_inner_most_message, &from_last_field) ==
            0) {
          to_refl->ClearField(to_inner_most_message, &to_last_field);
        } else {
          to_refl->MutableMessage(to_inner_most_message, &to_last_field)
              ->CopyFrom(from_refl->GetRepeatedMessage(*from_inner_most_message,
                                                       &from_last_field, 0));
        }
      } else if (to_last_field.is_repeated()) {
        to_refl->ClearField(to_inner_most_message, &to_last_field);
        to_refl->AddMessage(to_inner_most_message, &to_last_field)
            ->CopyFrom(from_refl->GetMessage(*from_inner_most_message,
                                             &from_last_field));
      } else {
        to_refl->MutableMessage(to_inner_most_message, &to_last_field)
            ->CopyFrom(from_refl->GetMessage(*from_inner_most_message,
                                             &from_last_field));
      }
      break;
    default:
      FUZZTEST_INTERNAL_CHECK(
          false, absl::StrCat("Unexpected type ", from_last_field.type_name()));
  }
}

std::vector<FieldPath> CollectAllFieldsImpl(
    const google::protobuf::Descriptor& message_descriptor,
    absl::flat_hash_set<const google::protobuf::Descriptor*>& visited_messages) {
  std::vector<FieldPath> results;
  if (visited_messages.contains(&message_descriptor)) {
    return results;
  }
  visited_messages.insert(&message_descriptor);
  for (size_t i = 0; i < message_descriptor.field_count(); ++i) {
    const google::protobuf::FieldDescriptor& field = *message_descriptor.field(i);
    FieldPath field_path;
    field_path.AppendField(field);
    results.push_back(field_path);
    // `GROUP` field is a deprecated way of expressing inner message.
    if (field.type() == google::protobuf::FieldDescriptor::TYPE_MESSAGE ||
        field.type() == google::protobuf::FieldDescriptor::TYPE_GROUP) {
      const google::protobuf::Descriptor& inner = *field.message_type();
      std::vector<FieldPath> inner_fields =
          CollectAllFieldsImpl(inner, visited_messages);
      for (const auto& loc : inner_fields) {
        FieldPath inner_field_path(field_path);
        inner_field_path.AppendPath(loc);
        results.push_back(inner_field_path);
      }
    }
  }
  return results;
}

std::vector<FieldPath> CollectAllFields(
    const google::protobuf::Descriptor& message_descriptor) {
  absl::flat_hash_set<const google::protobuf::Descriptor*> visited_messages;
  return CollectAllFieldsImpl(message_descriptor, visited_messages);
}

bool AreDifferentFieldsInSameOneOf(const google::protobuf::FieldDescriptor& a,
                                   const google::protobuf::FieldDescriptor& b) {
  if (&a == &b || a.containing_oneof() == nullptr ||
      b.containing_oneof() == nullptr)
    return false;
  return a.containing_oneof() == b.containing_oneof();
}

bool AreOneOfAltearnatives(const FieldPath& a, const FieldPath& b) {
  const std::vector<const google::protobuf::FieldDescriptor*>& a_fields =
      a.GetAllFields();
  const std::vector<const google::protobuf::FieldDescriptor*>& b_fields =
      b.GetAllFields();
  for (size_t i = 0; i < std::min(a_fields.size(), b_fields.size()); ++i) {
    const google::protobuf::FieldDescriptor& a_field = *a_fields[i];
    const google::protobuf::FieldDescriptor& b_field = *b_fields[i];
    if (AreDifferentFieldsInSameOneOf(a_field, b_field)) {
      return true;
    }
  }
  return false;
}

}  // namespace fuzztest::internal
