#include "./rpc_fuzzing/rpc_executor.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "./domain_tests/domain_testing.h"
#include "./rpc_fuzzing/grpc_stub.h"
#include "./rpc_fuzzing/proto_field_path.h"
#include "./rpc_fuzzing/rpc_sequence.h"
#include "./rpc_fuzzing/testdata/grpc/mini_blogger_service.h"
#include "./rpc_fuzzing/testdata/mini_blogger.pb.h"
#include "grpcpp//security/server_credentials.h"
#include "grpcpp//server.h"
#include "grpcpp//server_builder.h"
#include "grpcpp//support/channel_arguments.h"

namespace fuzztest::internal {

namespace {

using ::testing::AllOf;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::Ne;
using ::testing::NotNull;
using ::testing::Pointee;
using ::testing::ResultOf;

const google::protobuf::FieldDescriptor* GetField(const google::protobuf::Message& message,
                                        absl::string_view field_name) {
  return message.GetDescriptor()->FindFieldByName(field_name);
}

class RpcExecutorGrpcTest : public ::testing::Test {
 protected:
  RpcExecutorGrpcTest()
      : server_(grpc::ServerBuilder()
                    .RegisterService(&mini_blogger_service_)
                    .BuildAndStart()),
        stub_(server_->InProcessChannel(grpc::ChannelArguments())) {}

  ~RpcExecutorGrpcTest() override { server_->Shutdown(); }

  RpcNode GetRegisterUserRpcNode(absl::string_view user_name,
                                 absl::string_view email,
                                 absl::string_view password) {
    auto request = std::make_unique<RegisterUserRequest>();
    request->set_user_name(user_name);
    request->set_password(password);
    request->set_email(password);
    const google::protobuf::MethodDescriptor* method =
        google::protobuf::DescriptorPool::generated_pool()->FindMethodByName(
            "fuzztest.internal.MiniBlogger.RegisterUser");
    CHECK(method != nullptr);
    return RpcNode(*method, std::move(request));
  }

  MiniBloggerGrpcService mini_blogger_service_;
  std::unique_ptr<grpc::Server> server_ = nullptr;
  GrpcStub stub_;
};

TEST_F(RpcExecutorGrpcTest, ExecutorCorrectlyExecutesRpcCalls) {
  RpcNode node = GetRegisterUserRpcNode("test", "test_email@gmail.com", "123");
  RpcSequence sequence = {node};
  RpcExecutor executor(&stub_);
  ASSERT_OK(executor.Execute(sequence));
  EXPECT_THAT(executor.GetResponses(),
              ElementsAre(Pointee(ResultOf(
                  [](const google::protobuf::Message& response) {
                    return response.GetReflection()->GetBool(
                        response, GetField(response, "success"));
                  },
                  IsTrue()))));
}

}  // namespace
}  // namespace fuzztest::internal
