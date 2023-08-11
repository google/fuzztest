#include "./rpc_fuzzing/rpc_sequence.h"

#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"
#include "google/protobuf/util/message_differencer.h"
#include "absl/container/flat_hash_set.h"
#include "absl/memory/memory.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "./fuzztest/internal/logging.h"

namespace fuzztest::internal {

namespace {

std::vector<int> GetShuffledIndices(size_t size, absl::BitGenRef gen) {
  std::vector<int> shuffled_indices(size);
  std::iota(shuffled_indices.begin(), shuffled_indices.end(), 0);
  std::shuffle(shuffled_indices.begin(), shuffled_indices.end(), gen);
  return shuffled_indices;
}

std::vector<RpcNodeID> GetShuffledNodeIdsInGraph(const RpcDataFlowGraph& graph,
                                                 absl::BitGenRef gen) {
  std::vector<RpcNodeID> shuffled_node_ids;
  shuffled_node_ids.reserve(graph.NodeNum());
  for (const auto& [node_id, unused_node] : graph.GetAllNodes()) {
    shuffled_node_ids.push_back(node_id);
  }
  std::shuffle(shuffled_node_ids.begin(), shuffled_node_ids.end(), gen);
  return shuffled_node_ids;
}

void RemapRpcNodeIdToSequenceIndex(
    RpcSequence& sequence,
    const absl::flat_hash_map<RpcNodeID, RpcNodeID>& id_map) {
  for (RpcNode& node : sequence) {
    for (RpcDataFlowEdge& edge : node.dependencies()) {
      edge.from_node_id = id_map.at(edge.from_node_id);
    }
  }
}

void CollectTopologicalSortingOrder(const RpcDataFlowGraph& graph,
                                    RpcNodeID current_id, absl::BitGenRef gen,
                                    absl::flat_hash_set<RpcNodeID>& visited,
                                    std::vector<RpcNodeID>& sorted_ids) {
  if (visited.contains(current_id)) return;

  visited.insert(current_id);
  const RpcNode& node = graph.GetNode(current_id);
  std::vector<RpcNodeID> shuffled_edge_indices =
      GetShuffledIndices(node.dependencies().size(), gen);
  for (int edge_index : shuffled_edge_indices) {
    CollectTopologicalSortingOrder(graph,
                                   node.dependencies()[edge_index].from_node_id,
                                   gen, visited, sorted_ids);
  }
  sorted_ids.push_back(current_id);
}

std::vector<RpcNodeID> GetRandomTopologicalOrdering(
    const RpcDataFlowGraph& graph) {
  std::vector<RpcNodeID> sorted_node_ids;
  sorted_node_ids.reserve(graph.NodeNum());
  absl::flat_hash_set<RpcNodeID> visited;
  absl::BitGen gen;
  std::vector<RpcNodeID> shuffled_node_ids =
      GetShuffledNodeIdsInGraph(graph, gen);
  for (RpcNodeID node_id : shuffled_node_ids) {
    CollectTopologicalSortingOrder(graph, node_id, gen, visited,
                                   sorted_node_ids);
  }
  FUZZTEST_INTERNAL_CHECK(
      sorted_node_ids.size() == graph.NodeNum(),
      "Topological sort results in different number of nodes!");
  return sorted_node_ids;
}

RpcSequence SequentializeGraphByOrder(
    const RpcDataFlowGraph& graph, const std::vector<RpcNodeID>& node_order) {
  RpcSequence result;
  result.reserve(graph.NodeNum());
  absl::flat_hash_map<RpcNodeID /* original node id */,
                      RpcNodeID /* sequence index */>
      id_map;
  for (size_t seq_idx = 0; seq_idx < node_order.size(); ++seq_idx) {
    RpcNodeID original_node_id = node_order[seq_idx];
    id_map[original_node_id] = seq_idx;
    result.push_back(graph.GetNode(original_node_id));
  }
  RemapRpcNodeIdToSequenceIndex(result, id_map);
  return result;
}

}  // namespace

RpcNode::RpcNode(const RpcNode& other)
    : method_(other.method_),
      request_(absl::WrapUnique(other.request_->New())),
      dependencies_(other.dependencies_) {
  request_->CopyFrom(*other.request_);
}

RpcNode& RpcNode::operator=(const RpcNode& other) {
  method_ = other.method_;
  request_ = absl::WrapUnique(other.request_->New());
  request_->CopyFrom(*other.request_);
  dependencies_ = other.dependencies_;
  return *this;
}

bool operator==(const RpcDataFlowEdge& lhs, const RpcDataFlowEdge& rhs) {
  return lhs.from_node_id == rhs.from_node_id &&
         lhs.from_field == rhs.from_field && lhs.to_field == rhs.to_field;
}

bool operator!=(const RpcDataFlowEdge& lhs, const RpcDataFlowEdge& rhs) {
  return !(lhs == rhs);
}

bool operator==(const RpcNode& lhs, const RpcNode& rhs) {
  return lhs.method_->full_name() == rhs.method_->full_name() &&
         google::protobuf::util::MessageDifferencer::Equals(*lhs.request_,
                                                  *rhs.request_) &&
         lhs.dependencies_ == rhs.dependencies_;
}

bool operator!=(const RpcNode& lhs, const RpcNode& rhs) {
  return !(lhs == rhs);
}

void RpcDataFlowGraph::AddNode(RpcNodeID id, RpcNode rpc_node) {
  InvalidateNodeOrder();
  rpc_nodes_.emplace(id, rpc_node);
}

void RpcDataFlowGraph::RemoveNode(RpcNodeID id) {
  InvalidateNodeOrder();
  rpc_nodes_.erase(id);
}

const RpcNode& RpcDataFlowGraph::GetNode(RpcNodeID id) const {
  FUZZTEST_INTERNAL_CHECK(rpc_nodes_.contains(id), "Invalid id!");
  return rpc_nodes_.at(id);
}

size_t RpcDataFlowGraph::NodeNum() const { return rpc_nodes_.size(); }

RpcDataFlowGraph RpcDataFlowGraph::FromSequence(const RpcSequence& sequence) {
  RpcDataFlowGraph graph;
  for (int node_idx = 0; node_idx < sequence.size(); ++node_idx) {
    graph.AddNode(node_idx, sequence[node_idx]);
  }
  graph.node_order_ = std::vector<RpcNodeID>(sequence.size());
  std::iota(graph.node_order_->begin(), graph.node_order_->end(), 0);
  return graph;
}

RpcSequence RpcDataFlowGraph::GetSequence() const {
  if (!node_order_.has_value()) {
    node_order_ = GetRandomTopologicalOrdering(*this);
  }
  return SequentializeGraphByOrder(*this, *node_order_);
}

std::vector<RpcNodeID>& RpcDataFlowGraph::GetOrderedNodeIds() const {
  if (!node_order_.has_value()) {
    node_order_ = GetRandomTopologicalOrdering(*this);
  }
  return *node_order_;
}

bool operator==(const RpcDataFlowGraph& lhs, const RpcDataFlowGraph& rhs) {
  return lhs.GetSequence() == rhs.GetSequence();
}

bool operator!=(const RpcDataFlowGraph& lhs, const RpcDataFlowGraph& rhs) {
  return !(lhs == rhs);
}

void RpcDataFlowGraph::RandomizeTopologicalOrdering() { InvalidateNodeOrder(); }

}  // namespace fuzztest::internal
