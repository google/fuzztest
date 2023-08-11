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

#include <cstdint>
#include <vector>

#include "google/protobuf/descriptor.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./fuzztest/internal/test_protobuf.pb.h"
#include "./rpc_fuzzing/testdata/mini_blogger.pb.h"

namespace fuzztest::internal {

using ::testing::ElementsAre;
using ::testing::IsNull;
using ::testing::NotNull;
using ::testing::UnorderedElementsAre;

namespace {

TEST(FieldPathTest, GetFieldPathParseStringIntoAFieldPath) {
  const FieldPath field_path =
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id");
  EXPECT_THAT(
      field_path.GetAllFields(),
      ElementsAre(
          LogOutUserRequest::GetDescriptor()->FindFieldByName("log_out_info"),
          LogOutInfo::GetDescriptor()->FindFieldByName("session_info"),
          SessionInfo::GetDescriptor()->FindFieldByName("session_id")));
}

TEST(FieldPathTest, GetFieldPathAbortsAtInvalidField) {
  EXPECT_DEATH_IF_SUPPORTED(
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.invalid"),
      "Invalid field name!");
}

MATCHER_P(FieldPathAsString, path_str, "") {
  if (arg.GetAllFields().empty()) return path_str == "";
  std::string result;
  for (const google::protobuf::FieldDescriptor* part : arg.GetAllFields()) {
    absl::StrAppend(&result, part->name(), ".");
  }
  return result.substr(0, result.size() - 1) == path_str;
}

TEST(FieldPathTest, HashAndEqualityCheck) {
  const FieldPath path1 = GetFieldPath<LogInUserResponse>("session_id");
  const FieldPath path2 = GetFieldPath<LogInUserResponse>("session_id");
  EXPECT_EQ(path1, path2);
}

TEST(FieldPathTest, CopyFieldOfSameTypeAndSameNameInMessagesSucceeds) {
  // Test copying LogInUserResponse.session_id to
  // LogOutUserRequest.log_out_info.session_info.session_id.
  LogInUserResponse log_in_response;
  const FieldPath session_id_source_path =
      GetFieldPath<LogInUserResponse>("session_id");
  LogOutUserRequest log_out_request;
  const FieldPath session_id_sink_path =
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id");

  constexpr int64_t kSessionId = 0xdeadbeef;
  log_in_response.set_session_id(kSessionId);
  CopyField(session_id_source_path, log_in_response, session_id_sink_path,
            log_out_request);

  EXPECT_EQ(kSessionId,
            log_out_request.log_out_info().session_info().session_id());
}

TEST(FieldPathTest, CopyingRepeatedFieldToNonRepeatedCopiesTheFirstElement) {
  // Copy repeated `{val1, val2}` to non repeated `val2` results in `val2`.
  constexpr int64_t kValue1 = 123;
  constexpr int64_t kValue2 = 234;
  MessageContainingRepeatedFields message_containing_repeated_fields;
  message_containing_repeated_fields.add_field(kValue1);
  message_containing_repeated_fields.add_field(kValue2);
  const FieldPath source_path =
      GetFieldPath<MessageContainingRepeatedFields>("field");
  MessageNotContainingRepeatedFields message_not_containing_repeated_fields;
  message_not_containing_repeated_fields.set_field(kValue2);
  const FieldPath sink_path =
      GetFieldPath<MessageNotContainingRepeatedFields>("field");

  CopyField(source_path, message_containing_repeated_fields, sink_path,
            message_not_containing_repeated_fields);

  MessageNotContainingRepeatedFields expected_result;
  expected_result.set_field(kValue1);
  EXPECT_EQ(message_not_containing_repeated_fields.DebugString(),
            expected_result.DebugString());
}

TEST(FieldPathTest,
     CopyFieldDoesNothingIfSourceContainsEmptyRepeatedFieldInTheMiddle) {
  MessageContainingRepeatedFields message_containing_repeated_fields;
  const FieldPath source_path = GetFieldPath<MessageContainingRepeatedFields>(
      "repeated_msg_field.field2");
  MessageNotContainingRepeatedFields message_not_containing_repeated_fields;
  message_not_containing_repeated_fields.set_field2(123);
  const MessageNotContainingRepeatedFields expected_result =
      message_not_containing_repeated_fields;

  const FieldPath sink_path =
      GetFieldPath<MessageNotContainingRepeatedFields>("field2");

  CopyField(source_path, message_containing_repeated_fields, sink_path,
            message_not_containing_repeated_fields);
  EXPECT_EQ(message_not_containing_repeated_fields.DebugString(),
            expected_result.DebugString());
}

TEST(FieldPathTest,
     CopyFieldSucceedsIfSinkContainEmptyRepeatedFieldInTheMiddle) {
  constexpr int64_t kValue1 = 123;
  MessageContainingRepeatedFields message_containing_repeated_fields;
  const FieldPath sink_path = GetFieldPath<MessageContainingRepeatedFields>(
      "repeated_msg_field.field2");
  MessageNotContainingRepeatedFields message_not_containing_repeated_fields;
  message_not_containing_repeated_fields.set_field2(kValue1);

  const FieldPath source_path =
      GetFieldPath<MessageNotContainingRepeatedFields>("field2");

  CopyField(source_path, message_not_containing_repeated_fields, sink_path,
            message_containing_repeated_fields);
  MessageContainingRepeatedFields expected_result;
  expected_result.add_repeated_msg_field()->set_field2(kValue1);
  EXPECT_EQ(message_containing_repeated_fields.DebugString(),
            expected_result.DebugString());
}

TEST(FieldPathTest, CopyingEmptyRepeatedFieldToNonRepeatedClearsTheField) {
  // Copy empty repeated `{}` to non repeated `val2` results in cleared field.
  MessageContainingRepeatedFields message_containing_repeated_fields;
  const FieldPath source_path =
      GetFieldPath<MessageContainingRepeatedFields>("field");
  MessageNotContainingRepeatedFields message_not_containing_repeated_fields;
  message_not_containing_repeated_fields.set_field(123);
  const FieldPath sink_path =
      GetFieldPath<MessageNotContainingRepeatedFields>("field");

  CopyField(source_path, message_containing_repeated_fields, sink_path,
            message_not_containing_repeated_fields);

  EXPECT_EQ(message_not_containing_repeated_fields.DebugString(),
            MessageNotContainingRepeatedFields{}.DebugString());
}

TEST(FieldPathTest, CopyingNonRepeatedFieldToRepeatedFieldSetsFirstElement) {
  // Copy non repeated `val2` to repeated `{val1, val2}` results in `{val2}`.
  constexpr int64_t kValue1 = 123;
  constexpr int64_t kValue2 = 234;
  MessageNotContainingRepeatedFields message_not_containing_repeated_fields;
  message_not_containing_repeated_fields.set_field(kValue2);
  const FieldPath source_path =
      GetFieldPath<MessageNotContainingRepeatedFields>("field");

  MessageContainingRepeatedFields message_containing_repeated_fields;
  message_containing_repeated_fields.add_field(kValue1);
  message_containing_repeated_fields.add_field(kValue2);
  const FieldPath sink_path =
      GetFieldPath<MessageContainingRepeatedFields>("field");

  CopyField(source_path, message_not_containing_repeated_fields, sink_path,
            message_containing_repeated_fields);

  MessageContainingRepeatedFields expected_result;
  expected_result.add_field(kValue2);
  EXPECT_EQ(message_containing_repeated_fields.DebugString(),
            expected_result.DebugString());
}

TEST(FieldPathTest, CopyingRepeatedFieldHandlesFieldOfMessageTypeCorrectly) {
  MessageContainingRepeatedFields source_message, sink_message;
  source_message.add_repeated_msg_field()->set_field2(0x123);
  source_message.add_repeated_msg_field()->set_field2(0x234);
  const FieldPath field_path =
      GetFieldPath<MessageContainingRepeatedFields>("repeated_msg_field");

  CopyField(field_path, source_message, field_path, sink_message);

  EXPECT_EQ(sink_message.DebugString(), source_message.DebugString());
}

TEST(FieldPathTest,
     CopyingSIngularSrcToRepeatedDstHandlesFieldOfMessageTypeCorrectly) {
  MessageWithSingleInnerRepeated source_message;
  source_message.mutable_repeated_msg_field()->set_field2(123);
  MessageContainingRepeatedFields sink_message;
  sink_message.add_repeated_msg_field()->set_field2(1);
  sink_message.add_repeated_msg_field()->set_field2(1);
  const FieldPath sink_field_path =
      GetFieldPath<MessageContainingRepeatedFields>("repeated_msg_field");
  const FieldPath source_field_path =
      GetFieldPath<MessageWithSingleInnerRepeated>("repeated_msg_field");

  CopyField(source_field_path, source_message, sink_field_path, sink_message);

  MessageContainingRepeatedFields expected_result;
  expected_result.add_repeated_msg_field()->set_field2(123);

  EXPECT_EQ(sink_message.DebugString(), expected_result.DebugString());
}

TEST(FieldPathTest, CopyingRepeatedFieldToRepeatedFieldCopiesTheWholeVector) {
  // Copy repeated `{val1, val2}` to repeated `{}` results in `{val1, val2}`.
  constexpr int64_t kValue1 = 123;
  constexpr int64_t kValue2 = 234;

  MessageContainingRepeatedFields source, sink;
  source.add_field(kValue1);
  source.add_field(kValue2);

  const FieldPath source_path =
      GetFieldPath<MessageContainingRepeatedFields>("field");
  const FieldPath sink_path =
      GetFieldPath<MessageContainingRepeatedFields>("field");

  CopyField(source_path, source, sink_path, sink);

  MessageContainingRepeatedFields expected_result;
  expected_result.add_field(kValue1);
  expected_result.add_field(kValue2);
  EXPECT_EQ(sink.DebugString(), expected_result.DebugString());
}

TEST(FieldPathTest, CopyFieldOfSameTypeAndDifferentNameInMessagesFails) {
  // Test copying GetUserPostsOptions.order to
  // GetUserPostsRequest.options.
  GetUserPostsOptions options;
  const FieldPath order_source_path =
      GetFieldPath<GetUserPostsOptions>("order");
  GetUserPostsOptionsWithDifferentFieldNames options_with_different_field_names;
  const FieldPath ordering_sink_path =
      GetFieldPath<GetUserPostsOptionsWithDifferentFieldNames>("ordering");

  EXPECT_DEATH_IF_SUPPORTED(
      CopyField(order_source_path, options, ordering_sink_path,
                options_with_different_field_names),
      "Fields of mismatch names cannot be copied!");
}

TEST(FieldPathTest, CopyFieldOfDifferentTypeInMessagesFails) {
  // Test copying LogInUserResponse.session_id to
  // GetUserPostsRequest.options.
  const LogInUserResponse log_in_response;
  const FieldPath session_id_source_path =
      GetFieldPath<LogInUserResponse>("session_id");
  GetUserPostsRequest get_user_posts_request;
  const FieldPath session_id_sink_path =
      GetFieldPath<GetUserPostsRequest>("options");

  EXPECT_DEATH_IF_SUPPORTED(
      CopyField(session_id_source_path, log_in_response, session_id_sink_path,
                get_user_posts_request),
      "Fields of mismatch types cannot be copied!");
}

TEST(FieldPathTest, CopyFieldHandlesEnumCorrectly) {
  GetUserPostsOptions source_options, sink_options;
  const FieldPath field_path = GetFieldPath<GetUserPostsOptions>("order");
  source_options.set_order(SortingOrder::ASCENDING);

  CopyField(field_path, source_options, field_path, sink_options);

  EXPECT_EQ(sink_options.order(), SortingOrder::ASCENDING);
}

TEST(FieldPathTest, GetContainingMessageOfLastFieldReturnsContainingMessage) {
  const LogOutUserRequest log_out_request;
  const FieldPath session_id_sink_path =
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id");

  const LogOutInfo& log_out_info = log_out_request.log_out_info();
  const SessionInfo& session_info = log_out_info.session_info();

  const google::protobuf::Message* parent_msg =
      session_id_sink_path.GetContainingMessageOfLastField(log_out_request);

  EXPECT_EQ(parent_msg, &session_info);
}

TEST(FieldPathTest,
     GetContainingMessageReturnsNonNullForUnsetMiddleSingularField) {
  LogOutUserRequest log_out_request;
  const FieldPath session_id_sink_path =
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id");

  EXPECT_THAT(
      session_id_sink_path.GetContainingMessageOfLastField(log_out_request),
      NotNull());
}

TEST(FieldPathTest,
     GetContainingMessageReturnsNullForMissingMiddleRepeatedField) {
  MessageContainingRepeatedFields message_containing_repeated_fields;
  const FieldPath message_containing_repeated_fields_sink_path =
      GetFieldPath<MessageContainingRepeatedFields>(
          "repeated_msg_field.field2");
  EXPECT_THAT(
      message_containing_repeated_fields_sink_path
          .GetContainingMessageOfLastField(message_containing_repeated_fields),
      IsNull());
}

TEST(FieldPathTest,
     MutableContainingMessageAddMissingRepeatedFieldAndReturnsNonNull) {
  MessageContainingRepeatedFields message_containing_repeated_fields;
  const FieldPath message_containing_repeated_fields_sink_path =
      GetFieldPath<MessageContainingRepeatedFields>(
          "repeated_msg_field.field2");
  EXPECT_THAT(message_containing_repeated_fields_sink_path
                  .MutableContainingMessageOfLastField(
                      message_containing_repeated_fields),
              NotNull());
}

TEST(FieldPathTest,
     MutableContainingMessageAtNonEmptyRepeatedFieldWillNotAddField) {
  MessageContainingRepeatedFields message_containing_repeated_fields;
  message_containing_repeated_fields.add_repeated_msg_field()->set_field2(
      0x123);
  const FieldPath message_containing_repeated_fields_sink_path =
      GetFieldPath<MessageContainingRepeatedFields>(
          "repeated_msg_field.field2");
  (void)message_containing_repeated_fields_sink_path
      .MutableContainingMessageOfLastField(message_containing_repeated_fields);
  EXPECT_EQ(
      message_containing_repeated_fields.GetReflection()->FieldSize(
          message_containing_repeated_fields,
          message_containing_repeated_fields.GetDescriptor()->FindFieldByName(
              "repeated_msg_field")),
      1);
}

TEST(FieldPathTest, MutableContainingMessageAtEmptyRepeatedFieldWillAddField) {
  MessageContainingRepeatedFields message_containing_repeated_fields;
  const FieldPath message_containing_repeated_fields_sink_path =
      GetFieldPath<MessageContainingRepeatedFields>(
          "repeated_msg_field.field2");
  (void)message_containing_repeated_fields_sink_path
      .MutableContainingMessageOfLastField(message_containing_repeated_fields);
  EXPECT_EQ(
      message_containing_repeated_fields.GetReflection()->FieldSize(
          message_containing_repeated_fields,
          message_containing_repeated_fields.GetDescriptor()->FindFieldByName(
              "repeated_msg_field")),
      1);
}

TEST(FieldPathTest,
     GetContainingMessageOfLastFieldReturnsFirstIndexOfRepeatedFields) {
  MessageContainingRepeatedFields message;
  message.add_repeated_msg_field();
  message.add_repeated_msg_field();

  FieldPath field_path = GetFieldPath<MessageContainingRepeatedFields>(
      "repeated_msg_field.field2");

  const google::protobuf::Message* parent_msg =
      field_path.GetContainingMessageOfLastField(message);
  EXPECT_EQ(parent_msg, &message.repeated_msg_field(0));
}

TEST(FieldPathTest, MutableContainingMessageOfLastFieldReturnsMutableMessage) {
  LogOutUserRequest log_out_request;
  const FieldPath session_id_sink_path =
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id");

  const LogOutInfo& log_out_info = log_out_request.log_out_info();
  const SessionInfo& session_info = log_out_info.session_info();

  google::protobuf::Message* parent_msg =
      session_id_sink_path.MutableContainingMessageOfLastField(log_out_request);
  // MutableContainingMessageOfLastField might create new message so the address
  // will be different.
  EXPECT_NE(parent_msg, &session_info);
}

TEST(FieldPathTest, GetLastFieldReturnsLastFieldOfThePath) {
  const LogOutUserRequest log_out_request;
  const FieldPath session_id_sink_path =
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id");

  EXPECT_EQ(&session_id_sink_path.GetLastField(),
            SessionInfo::GetDescriptor()->FindFieldByName("session_id"));
}

TEST(FieldPathTest,
     AppendFieldSuccessIfTheLastFieldIsTheAppendedFieldParentType) {
  const FieldPath ground_truth =
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info");
  FieldPath field_path = GetFieldPath<LogOutUserRequest>("log_out_info");
  field_path.AppendField(
      *LogOutInfo::GetDescriptor()->FindFieldByName("session_info"));
  EXPECT_EQ(ground_truth, field_path);
}

TEST(FieldPathTest,
     AppendFieldFailsIfTheLastFieldIsNotTheAppendedFieldParentType) {
  FieldPath field_path = GetFieldPath<LogInUserResponse>("success");

  EXPECT_DEATH_IF_SUPPORTED(
      field_path.AppendField(field_path.GetLastField()),
      "The current last field in the path must be a message "
      "containing the appended field.");
}

TEST(FieldPathTest,
     AppendPathSuccessIfLastFieldOfAppendedPathIsContainedByTheCurrentPath) {
  const FieldPath ground_truth =
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id");
  FieldPath field_path1 = GetFieldPath<LogOutUserRequest>("log_out_info");
  const FieldPath field_path2 =
      GetFieldPath<LogOutInfo>("session_info.session_id");
  field_path1.AppendPath(field_path2);
  EXPECT_EQ(field_path1, ground_truth);
}

TEST(FieldPathTest,
     AppendPathFailsIfLastFieldOfAppendedPathIsNotContainedByTheCurrentPath) {
  FieldPath field_path1 = GetFieldPath<LogOutUserRequest>("log_out_info");
  const FieldPath field_path2 = GetFieldPath<SessionInfo>("session_id");

  EXPECT_DEATH_IF_SUPPORTED(
      field_path1.AppendPath(field_path2),
      "The current last field in the path must be a message "
      "containing the first field in the other path.");
}

TEST(FieldPathTest, CollectAllFieldsReturnAllInnerFields) {
  std::vector<FieldPath> all_fields =
      CollectAllFields(*LogOutUserRequest::descriptor());

  EXPECT_THAT(all_fields,
              UnorderedElementsAre(
                  FieldPathAsString("log_out_info"),
                  FieldPathAsString("log_out_info.session_info"),
                  FieldPathAsString("log_out_info.session_id"),
                  FieldPathAsString("log_out_info.session_info.session_id")));
}

TEST(FieldPathTest, CollectAllFieldsSupportsGroupField) {
  std::vector<FieldPath> all_fields =
      CollectAllFields(*MessageWithGroup::descriptor());

  EXPECT_THAT(all_fields,
              UnorderedElementsAre(FieldPathAsString("groupfield"),
                                   FieldPathAsString("groupfield.field1"),
                                   FieldPathAsString("groupfield.field2")));
}

TEST(FieldPathTest, CopyFieldsSupportsGroupField) {
  MessageWithGroup message_with_group1, message_with_group2;

  message_with_group1.mutable_groupfield()->set_field1(123);
  CopyField(GetFieldPath<MessageWithGroup>("groupfield"), message_with_group1,
            GetFieldPath<MessageWithGroup>("groupfield"), message_with_group2);
  EXPECT_EQ(message_with_group2.groupfield().field1(), 123);
}

TEST(FieldPathTest, CollectAllFieldsInRecursiveMessageSkipVisitedMessages) {
  std::vector<FieldPath> all_fields =
      CollectAllFields(*RecursiveNode::descriptor());
  EXPECT_THAT(all_fields, ElementsAre(FieldPathAsString("value"),
                                      FieldPathAsString("children")));
}

TEST(FieldPathTest, ToStringConcatAllFieldPartWithDot) {
  const FieldPath field_path =
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id");
  EXPECT_EQ(field_path.ToString(), "log_out_info.session_info.session_id");
}

TEST(FieldPathTest, AlternativeToReturnsTrueForFieldsWithinTheSameOneOf) {
  EXPECT_TRUE(
      AreOneOfAltearnatives(GetFieldPath<OneOfMessage>("oneof1_field1.v1"),
                            GetFieldPath<OneOfMessage>("oneof1_field2")));
  EXPECT_TRUE(
      AreOneOfAltearnatives(GetFieldPath<OneOfMessage>("oneof1_field1.v2"),
                            GetFieldPath<OneOfMessage>("oneof1_field2")));
}

TEST(FieldPathTest, AlternativeToReturnsFalseForFieldsNotWithinTheSameOneOf) {
  EXPECT_FALSE(
      AreOneOfAltearnatives(GetFieldPath<OneOfMessage>("oneof1_field1"),
                            GetFieldPath<OneOfMessage>("oneof1_field1.v1")));
  EXPECT_FALSE(
      AreOneOfAltearnatives(GetFieldPath<OneOfMessage>("oneof1_field1.v1"),
                            GetFieldPath<OneOfMessage>("oneof1_field1.v1")));
  EXPECT_FALSE(
      AreOneOfAltearnatives(GetFieldPath<OneOfMessage>("oneof1_field2"),
                            GetFieldPath<OneOfMessage>("oneof2_field2")));
}

}  // namespace

}  // namespace fuzztest::internal
