#ifndef FUZZTEST_RPC_FUZZING_SCAFFOLDING_STUB_H_
#define FUZZTEST_RPC_FUZZING_SCAFFOLDING_STUB_H_

#include <memory>
#include <utility>

#include "net/rpc/anonymous-stub.h"
#include "net/rpc2/rpc2.h"
#include "absl/status/statusor.h"
#include "./rpc_fuzzing/rpc_stub.h"

namespace fuzztest {

class ScaffoldingStub : public RpcStub {
 public:
  ScaffoldingStub(absl::string_view socket)
      : stub_(std::make_unique<AnonymousStub>(
            rpc2::CreateClientChannel(socket))) {}
  ScaffoldingStub(std::unique_ptr<AnonymousStub> stub)
      : stub_(std::move(stub)) {}
  absl::StatusOr<std::unique_ptr<google::protobuf::Message>> CallMethod(
      const google::protobuf::MethodDescriptor& method_descriptor,
      const google::protobuf::Message& request) override;

 private:
  std::unique_ptr<AnonymousStub> stub_;
};

}  // namespace fuzztest

#endif  // FUZZTEST_RPC_FUZZING_SCAFFOLDING_STUB_H_
