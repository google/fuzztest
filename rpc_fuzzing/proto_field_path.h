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

#ifndef FUZZTEST_RPC_FUZZING_PROTO_FIELD_PATH_H_
#define FUZZTEST_RPC_FUZZING_PROTO_FIELD_PATH_H_

#include <vector>

#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"

namespace fuzztest::internal {

// Represent a path to a (sub)field in a message.
class FieldPath {
 public:
  // Append a field as a part to the path.
  void AppendField(const google::protobuf::FieldDescriptor& field);
  // Append another path to the path.
  void AppendPath(const FieldPath& other);

  // Given a message, follow the field path and return the parent message of the
  // last field. If any repeated field in the middle is empty, return nullptr
  const google::protobuf::Message* GetContainingMessageOfLastField(
      const google::protobuf::Message& message) const;
  // The mutable version fills in empty fields along the path, and thus never
  // returns a null pointer.
  google::protobuf::Message* MutableContainingMessageOfLastField(
      google::protobuf::Message& message) const;

  // Get the last field in the path.
  const google::protobuf::FieldDescriptor& GetLastField() const;
  // Get all the parts of the path.
  const std::vector<const google::protobuf::FieldDescriptor*>& GetAllFields() const;

  // Returns a string concatenating all the field parts by ".". For example, a
  // field path with two fields "field1" and "field2" will return
  // "field1.field2".
  std::string ToString() const;

 private:
  bool CanAppend(const google::protobuf::FieldDescriptor& field) const;

  // Make FieldPath hashable.
  template <typename H>
  friend H AbslHashValue(H h, const FieldPath& m) {
    h = H::combine_contiguous(std::move(h), m.field_descriptors_.data(),
                              m.field_descriptors_.size());
    return h;
  }
  friend bool operator==(const FieldPath& lhs, const FieldPath& rhs);

  // A list of fields that allow us to locate inner fields.
  std::vector<const google::protobuf::FieldDescriptor*> field_descriptors_;
};

bool operator==(const FieldPath& lhs, const FieldPath& rhs);

// Utility function for copying fields in different proto messages, the fields
// should have the same names and types, otherwise an assertion will be
// triggered. If the source field is repeated but the sink is not, we copy the
// first element of the source. If the source field is not repeated but the sink
// is, we clear the sink and copy the source as the first element of the sink.
// TODO(changochen): Make the condition of same name optional.
// TODO(changochen): Select random element of a repeated fields for copying.
void CopyField(const FieldPath& from_field, const google::protobuf::Message& from,
               const FieldPath& to_field, google::protobuf::Message& to);

FieldPath GetFieldPathWithDescriptor(const google::protobuf::Descriptor& descriptor,
                                     std::string_view field_path_str);

// Get a field path in a message from a path string. The path string should be
// in format like "field1.subfield2.subfield3.xxx".
// TODO(changochen): Return absl::StatusOr<FieldPath> instead of aborting. Make
// this a constructor of field path.
template <typename MessageT>
FieldPath GetFieldPath(std::string_view field_path_str) {
  const google::protobuf::Descriptor* descriptor = MessageT::GetDescriptor();
  return GetFieldPathWithDescriptor(*descriptor, field_path_str);
}

// Utility function for collecting all (sub)fields in message type. If the
// message type is recursive, then we only collect fields in a message when we
// see its type for the first time.
std::vector<FieldPath> CollectAllFields(
    const google::protobuf::Descriptor& message_descriptor);

// Checks whether two fields path are alternatives to each other (i.e., within
// the same oneof group). If yes, only at most one of them should be set at any
// given time.
// For example, the following message: message Message {
//    oneof test_one_of {
//        Message1 a = 1;
//        int b = 2;
//    }
// }
//
// message Message1 {
//   int a1 = 1;
//   int a2 = 2;
// }
//
// We consider that a.a1 and b are within the same oneof, therefore
// "alternatives", while a.a1 and a.a2 are not.
bool AreOneOfAltearnatives(const FieldPath& a, const FieldPath& b);

}  // namespace fuzztest::internal

#endif  // FUZZTEST_RPC_FUZZING_PROTO_FIELD_PATH_H_
