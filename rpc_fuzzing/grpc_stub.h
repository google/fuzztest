#ifndef FUZZTEST_RPC_FUZZING_GRPC_STUB_H_
#define FUZZTEST_RPC_FUZZING_GRPC_STUB_H_
#include <memory>

#include "google/protobuf/message.h"
#include "absl/status/statusor.h"
#include "./rpc_fuzzing/rpc_stub.h"
#include "grpcpp//generic/generic_stub.h"

namespace fuzztest {

using GrpcGenericStub =
    grpc::TemplatedGenericStub<google::protobuf::Message, google::protobuf::Message>;

class GrpcStub : public RpcStub {
 public:
  GrpcStub(std::shared_ptr<grpc::ChannelInterface> channel)
      : grpc_stub_(
            std::make_unique<
                grpc::TemplatedGenericStub<google::protobuf::Message, google::protobuf::Message>>(
                channel)) {}
  absl::StatusOr<std::unique_ptr<google::protobuf::Message>> CallMethod(
      const google::protobuf::MethodDescriptor& method_descriptor,
      const google::protobuf::Message& request) override;

 private:
  std::unique_ptr<GrpcGenericStub> grpc_stub_ = nullptr;
};

}  // namespace fuzztest

#endif  // FUZZTEST_RPC_FUZZING_GRPC_STUB_H_
