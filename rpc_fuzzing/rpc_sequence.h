#ifndef FUZZTEST_RPC_FUZZING_RPC_SEQUENCE_H_
#define FUZZTEST_RPC_FUZZING_RPC_SEQUENCE_H_

#include <memory>
#include <optional>
#include <vector>

#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"
#include "absl/container/flat_hash_map.h"
#include "./rpc_fuzzing/proto_field_path.h"

namespace fuzztest::internal {

// An RPC call is identified by an id because we might have multiple calls to
// the same rpc method. In the sequence, the id is also the index of the node.
using RpcNodeID = std::int32_t;

// Represents a data-flow edge between two RPC calls.
struct RpcDataFlowEdge {
  RpcNodeID from_node_id = -1;
  // The message field in the response.
  FieldPath from_field;
  // The dynamic field in the request.
  FieldPath to_field;
};

bool operator==(const RpcDataFlowEdge& lhs, const RpcDataFlowEdge& rhs);
bool operator!=(const RpcDataFlowEdge& lhs, const RpcDataFlowEdge& rhs);

// Represents a remote procedure call (a request). Parts of the request that are
// coming from a previous response are represented with a data flow edge
// (`RpcDataFlowEdge`).
class RpcNode {
 public:
  RpcNode(const google::protobuf::MethodDescriptor& method,
          std::unique_ptr<google::protobuf::Message> request)
      : method_(&method), request_(std::move(request)) {}
  RpcNode(const RpcNode&);
  RpcNode(RpcNode&&) noexcept;
  RpcNode& operator=(const RpcNode&);
  RpcNode& operator=(RpcNode&&) = default;
  const google::protobuf::MethodDescriptor& method() const { return *method_; }
  google::protobuf::Message& request() { return *request_; }
  const google::protobuf::Message& request() const { return *request_; }
  void AddDependency(RpcDataFlowEdge dep) { dependencies_.push_back(dep); }
  const std::vector<RpcDataFlowEdge>& dependencies() const {
    return dependencies_;
  }
  std::vector<RpcDataFlowEdge>& dependencies() { return dependencies_; }

  friend bool operator==(const RpcNode& lhs, const RpcNode& rhs);

 private:
  // The `method_` is ensured to be non-null.
  const google::protobuf::MethodDescriptor* method_;
  std::unique_ptr<google::protobuf::Message> request_;
  std::vector<RpcDataFlowEdge> dependencies_;
};

bool operator==(const RpcNode& lhs, const RpcNode& rhs);
bool operator!=(const RpcNode& lhs, const RpcNode& rhs);

inline RpcNode::RpcNode(RpcNode&&) noexcept = default;

// The RpcSequence represents a topologically sorted RpcDataFlowGraph.
using RpcSequence = std::vector<RpcNode>;

// The RpcDataFlowGraph represents a "remote procedure call session", i.e., a
// set of RPC method calls and the data-flow dependencies between them.
class RpcDataFlowGraph {
 public:
  void AddNode(RpcNodeID id, RpcNode rpc_node);
  void RemoveNode(RpcNodeID id);
  const RpcNode& GetNode(RpcNodeID id) const;
  size_t NodeNum() const;

  absl::flat_hash_map<RpcNodeID, RpcNode>& GetAllNodes() { return rpc_nodes_; }
  const absl::flat_hash_map<RpcNodeID, RpcNode>& GetAllNodes() const {
    return rpc_nodes_;
  }

  // Returns a topologically sorted sequence representation of the graph. Note
  // that there are multiple possible topological orderings, from which it
  // returns a random one. Multiple calls to the method return the same ordering
  // (unless RandomizeTopologicalOrdering() is called).
  RpcSequence GetSequence() const;

  // Converts a sequence to a graph with the sequence node ordering.
  static RpcDataFlowGraph FromSequence(const RpcSequence& sequence);

  // Randomizes the topological ordering of the nodes.
  void RandomizeTopologicalOrdering();

  // Returns the ordering of the nodes corresponding to that returned by
  // `GetSequence`.
  std::vector<RpcNodeID>& GetOrderedNodeIds() const;

 private:
  // Invalidates the node order so that if the order is needed again it will be
  // re-computed on demand. This optimization avoids unnecessary recomputation
  // every time the graph is changed because the recomputation can be costly.
  void InvalidateNodeOrder() const { node_order_.reset(); }
  absl::flat_hash_map<RpcNodeID, RpcNode> rpc_nodes_;
  // `GetSequence` might change the order so we need `mutable` for `GetSequence`
  // to be used in `FromValue` in the RpcSession domain.
  mutable std::optional<std::vector<RpcNodeID>> node_order_;
};

// Returns true if the graphs have the same nodes and ordering.
bool operator==(const RpcDataFlowGraph& lhs, const RpcDataFlowGraph& rhs);
bool operator!=(const RpcDataFlowGraph& lhs, const RpcDataFlowGraph& rhs);

}  // namespace fuzztest::internal

#endif  // FUZZTEST_RPC_FUZZING_RPC_SEQUENCE_H_
