#include "./rpc_fuzzing/rpc_executor.h"

#include <memory>
#include <utility>
#include <vector>

#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "./fuzztest/internal/logging.h"

namespace fuzztest::internal {

absl::Status RpcExecutor::Execute(RpcSequence& sequence) {
  responses_.clear();
  responses_.reserve(sequence.size());
  absl::Status status;
  for (RpcNode& node : sequence) {
    status = ExecuteOne(node);
    if (!status.ok()) {
      return status;
    }
  }
  return status;
}

const google::protobuf::Message& RpcExecutor::GetRpcNodeResponse(RpcNodeID node_id) {
  FUZZTEST_INTERNAL_CHECK(node_id < responses_.size(),
                          "The dependency source doesn't exist!");
  return *responses_[node_id];
}

std::vector<const google::protobuf::Message*> RpcExecutor::GetResponses() const {
  std::vector<const google::protobuf::Message*> responses;
  responses.reserve(responses_.size());
  for (const std::unique_ptr<google::protobuf::Message>& response : responses_) {
    responses.push_back(response.get());
  }
  return responses;
}

absl::Status RpcExecutor::ExecuteOne(RpcNode& node) {
  for (const RpcDataFlowEdge& dep : node.dependencies()) {
    // Assign value to dynamic fields.
    const google::protobuf::Message& save_response = GetRpcNodeResponse(dep.from_node_id);
    CopyField(dep.from_field, save_response, dep.to_field, node.request());
  }

  absl::StatusOr<std::unique_ptr<google::protobuf::Message>> response =
      stub_->CallMethod(node.method(), node.request());
  if (!response.ok()) return std::move(response).status();
  responses_.push_back(*std::move(response));
  return absl::OkStatus();
}

}  // namespace fuzztest::internal
