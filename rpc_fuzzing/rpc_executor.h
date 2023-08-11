#ifndef FUZZTEST_RPC_FUZZING_RPC_EXECUTOR_H_
#define FUZZTEST_RPC_FUZZING_RPC_EXECUTOR_H_

#include <memory>
#include <vector>

#include "google/protobuf/message.h"
#include "absl/log/die_if_null.h"
#include "./rpc_fuzzing/rpc_sequence.h"
#include "./rpc_fuzzing/rpc_stub.h"
namespace fuzztest::internal {

// The RpcExecutor fills the dynamic values from the previous responses
// according to the dependency in the RpcSequence and sends modified requests to
// the fuzzed service.
class RpcExecutor {
 public:
  RpcExecutor(RpcStub* stub) : stub_(ABSL_DIE_IF_NULL(stub)) {}
  // Send the rpc calls specified in `sequence`. The requests of `sequence` will
  // be modified according to the dependency. Every time this method is called,
  // the previous responses will be cleared.
  absl::Status Execute(RpcSequence& sequence);
  // Get the responses of the last executed sequence.
  std::vector<const google::protobuf::Message*> GetResponses() const;

 private:
  // Fill the dynamic fields in the request, execute a single RPC call, saves
  // and returns the status of the rpc.
  absl::Status ExecuteOne(RpcNode& node);
  const google::protobuf::Message& GetRpcNodeResponse(RpcNodeID node_id);

  std::vector<std::unique_ptr<google::protobuf::Message>> responses_;
  RpcStub* stub_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_RPC_FUZZING_RPC_EXECUTOR_H_
