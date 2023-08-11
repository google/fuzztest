#ifndef FUZZTEST_RPC_FUZZING_RPC_SESSION_H_
#define FUZZTEST_RPC_FUZZING_RPC_SESSION_H_

#include <algorithm>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"
#include "absl/container/flat_hash_map.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/protobuf_domain_impl.h"
#include "./fuzztest/internal/domains/value_mutation_helpers.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/table_of_recent_compares.h"
#include "./fuzztest/internal/type_support.h"
#include "./rpc_fuzzing/proto_field_path.h"
#include "./rpc_fuzzing/rpc_executor.h"
#include "./rpc_fuzzing/rpc_potential_dfg.h"
#include "./rpc_fuzzing/rpc_sequence.h"

namespace fuzztest {

namespace internal {

// A helper domain that allows its inner domain to be lazily initialized.
template <typename DomainT, typename... Args>
class Lazy : public DomainBase<Lazy<DomainT, Args...>, value_type_t<DomainT>,
                               corpus_type_t<DomainT>> {
 public:
  using typename Lazy::DomainBase::corpus_type;
  using typename Lazy::DomainBase::value_type;

  Lazy(Args&&... args) : args_(std::forward<Args>(args)...) {}

  Lazy(const Lazy& other) {
    if (other.inner_ != nullptr) {
      inner_ = std::make_unique<DomainT>(*other.inner_);
    }
    args_ = other.args_;
  }

  Lazy(Lazy&& other) noexcept = default;
  Lazy& operator=(Lazy&& other) = default;
  corpus_type Init(absl::BitGenRef prng) { return GetInnerDomain().Init(prng); }

  void Mutate(corpus_type& corpus_value, absl::BitGenRef prng,
              bool shrink_only) {
    GetInnerDomain().Mutate(corpus_value, prng, shrink_only);
  }

  value_type GetValue(const corpus_type& corpus_value) const {
    return GetInnerDomain().GetValue(corpus_value);
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    return GetInnerDomain().FromValue(v);
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    return GetInnerDomain().ParseCorpus(obj);
  }

  IRObject SerializeCorpus(const corpus_type& corpus_value) const {
    return GetInnerDomain().SerializeCorpus(corpus_value);
  }

  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const {
    return GetInnerDomain().ValidateCorpusValue(corpus_value);
  }

  auto GetPrinter() const { return GetInnerDomain().GetPrinter(); }

 private:
  template <std::size_t... Is>
  std::unique_ptr<DomainT> CreateInner(std::tuple<Args...> tup,
                                       std::index_sequence<Is...>) const {
    return std::make_unique<DomainT>(std::move(std::get<Is>(tup))...);
  }

  const DomainT& GetInnerDomain() const {
    if (inner_ == nullptr) {
      inner_ = CreateInner(args_, std::index_sequence_for<Args...>{});
    }
    return *inner_;
  }

  DomainT& GetInnerDomain() {
    if (inner_ == nullptr) {
      inner_ = CreateInner(args_, std::index_sequence_for<Args...>{});
    }
    return *inner_;
  }
  mutable std::unique_ptr<DomainT> inner_ = nullptr;
  mutable std::tuple<Args...> args_;
};

template <class T>
const T& PickRandomElement(const std::vector<T>& vec, absl::BitGenRef prng) {
  FUZZTEST_INTERNAL_CHECK(!vec.empty(),
                          "Cannot pick elements from an empy vector.");
  return vec[absl::Uniform(prng, size_t{0}, vec.size())];
}

// Rpc session domain. It generates RPC sequences with data-flows between
// requests and responses of calls. The provided RpcSequence can be consumed by
// the RpcExecutor.
template <typename ServiceT = void>
class RpcSessionImpl : public DomainBase<RpcSessionImpl<ServiceT>, RpcSequence,
                                         RpcDataFlowGraph> {
 public:
  using typename RpcSessionImpl::DomainBase::corpus_type;
  using typename RpcSessionImpl::DomainBase::value_type;

  // `service_factory` should return the fully qualified service name such as
  // `package.Service`.
  RpcSessionImpl(std::function<absl::string_view()> service_factory)
      : abstract_dfg_(CreatePotentialDfgByServiceName(service_factory())) {
    const google::protobuf::ServiceDescriptor& desc =
        GetServiceDescriptorByServiceName(service_factory());
    Initialize(desc);
  }

  template <typename T = ServiceT,
            typename = std::enable_if_t<is_stubby_service<T>::value ||
                                        is_grpc_service<T>::value ||
                                        std::is_same_v<T, google::protobuf::Service>>>
  RpcSessionImpl() : abstract_dfg_(CreatePotentialDfg<ServiceT>()) {
    const google::protobuf::ServiceDescriptor& desc = GetServiceDescriptor<ServiceT>();
    Initialize(desc);
  }

  // Generate a sequence containing only a single rpc call. Such calls should be
  // the "roots" in the data flow graph and depend on no other nodes.
  corpus_type Init(absl::BitGenRef prng) {
    const google::protobuf::MethodDescriptor& method =
        *PickRandomElement(all_methods_, prng);
    RpcDataFlowGraph result;
    auto& request_domain = GetRequestDomain(method);
    RpcNode call_node(method,
                      request_domain.GetValue(request_domain.Init(prng)));
    result.AddNode(0 /* the first node */, std::move(call_node));
    return result;
  }

  void Mutate(corpus_type& graph, absl::BitGenRef prng, bool only_shrink) {
    if (only_shrink) {
      RunOne(
          prng, [&] { DeleteTailCall(graph, prng); },
          [&] { MutateStaticField(graph, prng, only_shrink); });
    } else {
      RunOne(
          prng, [&] { InsertTailCall(graph, prng); },
          [&] { DeleteTailCall(graph, prng); },
          [&] { MutateStaticField(graph, prng, only_shrink); });
    }
  }

  value_type GetValue(const corpus_type& graph) const {
    return graph.GetSequence();
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    corpus_type result;
    for (size_t i = 0; i < v.size(); ++i) {
      result.AddNode(i, v[i]);
    }
    return result;
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    auto subs = obj.Subs();
    if (!subs || subs->empty()) {
      return std::nullopt;
    }
    RpcSequence sequence;
    sequence.reserve(subs->size());
    for (const auto& node_obj : *subs) {
      if (!ValidateRpcNodeObjFormat(node_obj)) return std::nullopt;
      auto node = ParseRpcNodeMethodAndRequest(node_obj);
      if (!node) return std::nullopt;
      auto edges_sub = (*node_obj.Subs())[2].Subs();
      for (const auto& edge_obj : *edges_sub) {
        std::optional<RpcDataFlowEdge> edge =
            ParseRpcDataFlowEdge(edge_obj, sequence, node->method());
        if (!edge) return std::nullopt;
        node->AddDependency(*edge);
      }
      sequence.push_back(*std::move(node));
    }
    return RpcDataFlowGraph::FromSequence(sequence);
  }

  // Serializes the graph in the topological-sorting order.
  IRObject SerializeCorpus(const corpus_type& graph) const {
    IRObject result;
    std::vector<IRObject>& result_subs = result.MutableSubs();
    // We serialize the sequence instead to avoid storing the RpcNodeID.
    for (const RpcNode& node : graph.GetSequence()) {
      result_subs.push_back(SerializeRpcNode(node));
    }
    return result;
  }

  // TODO(changochen): Implemented in later CL.
  auto GetPrinter() const { return MonostatePrinter{}; }

  // Check whether every RpcNode:
  // 1. Only depend on previous nodes. (No cyclic dependencies)
  // 2. Every dependency matches one of the potential dependencies.
  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const {
    absl::flat_hash_set<RpcNodeID> previous_node_ids;
    for (RpcNodeID node_id : corpus_value.GetOrderedNodeIds()) {
      const RpcNode& node = corpus_value.GetNode(node_id);
      const RpcPotentialDfgNode& dfg_node =
          abstract_dfg_.GetNode(node.method());
      absl::flat_hash_set<FieldPath> all_sink_paths;
      for (const RpcDataFlowEdge& edge : node.dependencies()) {
        // The current node should only depend on previous nodes.
        if (!previous_node_ids.contains(edge.from_node_id))
          return absl::InvalidArgumentError(
              "The dependencies should only come from previously executed "
              "nodes.");
        if (!dfg_node.GetAllDependencies().contains(edge.to_field)) {
          return absl::InvalidArgumentError(
              "The sink field should be defined in the potential data flow "
              "graph.");
        }

        if (all_sink_paths.contains(edge.to_field)) {
          return absl::InvalidArgumentError(
              "One sink field should have at most one concrete dependency!");
        }
        all_sink_paths.insert(edge.to_field);

        // Check whether the dependency source from `edge` actually matches one
        // of the potential dependency source.
        if (!HasPotentialSourceForEdge(edge, corpus_value, dfg_node)) {
          return absl::InvalidArgumentError(
              "The dependency is not defined in the potential data flow "
              "graph.");
        }
      }

      previous_node_ids.insert(node_id);
    }
    return absl::OkStatus();
  }

 private:
  void Initialize(const google::protobuf::ServiceDescriptor& desc) {
    for (int i = 0; i < desc.method_count(); ++i) {
      const google::protobuf::MethodDescriptor* method = desc.method(i);
      all_methods_.push_back(method);

      std::function<const google::protobuf::Message*()> get_request_prototype =
          [method]() {
            return google::protobuf::MessageFactory::generated_factory()->GetPrototype(
                method->input_type());
          };
      request_domains_.emplace(
          method, ProtobufDomainUntypedImpl<google::protobuf::Message>(
                      PrototypePtr<google::protobuf::Message>(get_request_prototype),
                      /*use_lazy_initialization=*/false));
    }
  }

  bool AllPotentialDepsInDfgNodeCanBeSatisfied(
      const absl::flat_hash_set<FieldPath>& satisfied_field_paths,
      const RpcPotentialDfgNode& dfg_node) const {
    for (const auto& [field_path, unused] : dfg_node.GetAllDependencies()) {
      if (!satisfied_field_paths.contains(field_path)) {
        bool can_be_satisfied = false;
        for (const FieldPath& satisfied_field_path : satisfied_field_paths) {
          if (AreOneOfAltearnatives(satisfied_field_path, field_path)) {
            can_be_satisfied = true;
            break;
          }
        }
        if (!can_be_satisfied) return false;
      }
    }
    return true;
  }
  // Check whether the source of the edge is defined in the potential data flow
  // graph.
  bool HasPotentialSourceForEdge(const RpcDataFlowEdge& edge,
                                 const RpcDataFlowGraph& graph,
                                 const RpcPotentialDfgNode& dfg_node) const {
    for (const RpcPotentialDfgNode::PotentialDependencySource&
             potential_source : dfg_node.GetDependencies(edge.to_field)) {
      const RpcNode& from_node = graph.GetNode(edge.from_node_id);
      if (potential_source.method == &from_node.method() &&
          potential_source.field_path == edge.from_field) {
        return true;
      }
    }
    return false;
  }

  bool ValidateRpcNodeObjFormat(const IRObject& obj) const {
    auto node_subs = obj.Subs();
    // Each node has a sub of size 3: method, request, dependencies.
    if (!node_subs || node_subs->size() != 3) {
      return false;
    }
    auto edge_subs = (*node_subs)[2].Subs();
    if (!edge_subs) {
      return false;
    }
    // Each edge has a sub of size 3: from_id, from_field, to_field.
    for (const auto& edge_sub : *edge_subs) {
      if (!edge_sub.Subs() || edge_sub.Subs()->size() != 3) {
        return false;
      }
    }
    return true;
  }

  IRObject SerializeRpcDataFlowEdge(const RpcDataFlowEdge& edge) const {
    IRObject edge_obj;
    std::vector<IRObject>& edge_subs = edge_obj.MutableSubs();
    edge_subs.push_back(IRObject::FromCorpus(edge.from_node_id));
    edge_subs.push_back(IRObject::FromCorpus(edge.from_field.ToString()));
    edge_subs.push_back(IRObject::FromCorpus(edge.to_field.ToString()));
    return edge_obj;
  }

  IRObject SerializeRpcNode(const RpcNode& node) const {
    // The serialized object will be like
    // [ method_name, request_proto_buf_string, [edges]]
    IRObject node_obj;
    std::vector<IRObject>& node_subs = node_obj.MutableSubs();
    node_subs.push_back(IRObject::FromCorpus(node.method().full_name()));
    node_subs.push_back(
        IRObject::FromCorpus(node.request().SerializeAsString()));
    IRObject edges_obj;
    if (!node.dependencies().empty()) {
      std::vector<IRObject>& edges_subs = edges_obj.MutableSubs();
      for (const RpcDataFlowEdge& edge : node.dependencies()) {
        edges_subs.push_back(SerializeRpcDataFlowEdge(edge));
      }
    }
    node_subs.push_back(std::move(edges_obj));
    return node_obj;
  }

  std::optional<RpcDataFlowEdge> ParseRpcDataFlowEdge(
      const IRObject& edge_obj, const RpcSequence& sequence,
      const google::protobuf::MethodDescriptor& to_method) const {
    auto edge_subs = edge_obj.Subs();
    FUZZTEST_INTERNAL_CHECK(edge_subs && edge_subs->size() == 3,
                            "Invalid edge format!");
    auto from_node_id = (*edge_subs)[0].ToCorpus<RpcNodeID>();
    auto from_field_str = (*edge_subs)[1].ToCorpus<std::string>();
    auto to_field_str = (*edge_subs)[2].ToCorpus<std::string>();
    if (!from_node_id || !from_field_str || !to_field_str) {
      return std::nullopt;
    }
    if (*from_node_id >= sequence.size()) return std::nullopt;
    FieldPath from_field_path = GetFieldPathWithDescriptor(
        *sequence[*from_node_id].method().output_type(), *from_field_str);
    FieldPath to_field_path =
        GetFieldPathWithDescriptor(*to_method.input_type(), *to_field_str);
    return RpcDataFlowEdge{*from_node_id, from_field_path, to_field_path};
  }

  std::optional<RpcNode> ParseRpcNodeMethodAndRequest(
      const IRObject& obj) const {
    const google::protobuf::DescriptorPool& pool =
        *google::protobuf::DescriptorPool::generated_pool();
    auto node_subs = obj.Subs();
    std::optional<std::string> method_name =
        (*node_subs)[0].ToCorpus<std::string>();
    if (!method_name) return std::nullopt;
    const google::protobuf::MethodDescriptor* method =
        pool.FindMethodByName(*method_name);

    if (!method) return std::nullopt;

    std::optional<std::string> request_str =
        (*node_subs)[1].ToCorpus<std::string>();

    std::unique_ptr<google::protobuf::Message> request =
        absl::WrapUnique(google::protobuf::MessageFactory::generated_factory()
                             ->GetPrototype(method->input_type())
                             ->New());
    if (!request->ParseFromString(*request_str)) return std::nullopt;

    return RpcNode(*method, std::move(request));
  }

  absl::flat_hash_set<FieldPath> CollectSatisfiableFields(
      const RpcPotentialDfgNode& dfg_node,
      const absl::flat_hash_map<const google::protobuf::MethodDescriptor*,
                                std::vector<RpcNodeID>>& existing_nodes) {
    absl::flat_hash_set<FieldPath> satisfied_fields;
    for (const auto& [field_path, source_vec] : dfg_node.GetAllDependencies()) {
      for (const RpcPotentialDfgNode::PotentialDependencySource& source :
           source_vec) {
        if (existing_nodes.contains(source.method)) {
          satisfied_fields.insert(field_path);
          break;
        }
      }
    }
    return satisfied_fields;
  }

  std::vector<FieldPath> RemoveAlternativeFieldPath(
      const absl::flat_hash_set<FieldPath>& field_paths, absl::BitGenRef prng) {
    std::vector<FieldPath> result;
    std::vector<FieldPath> field_paths_vec(field_paths.begin(),
                                           field_paths.end());
    std::shuffle(field_paths_vec.begin(), field_paths_vec.end(), prng);
    for (const FieldPath& field_path : field_paths_vec) {
      bool found_same_one_of_field = false;
      for (const FieldPath& other_field_path : result) {
        if (AreOneOfAltearnatives(field_path, other_field_path)) {
          found_same_one_of_field = true;
          break;
        }
      }
      if (!found_same_one_of_field) {
        result.push_back(field_path);
      }
    }
    return result;
  }

  // Checks whether all the dependencies of `dfg_node` can be satisfied by the
  // nodes in `existing_nodes`. "Satisfy" means there is at least one
  // potential dependency of any field in the node that has its source in the
  // rpc data flow graph.
  bool DependsOnAndCanBeSatisfiedBy(
      const RpcPotentialDfgNode& dfg_node,
      const absl::flat_hash_map<const google::protobuf::MethodDescriptor*,
                                std::vector<RpcNodeID>>& existing_nodes) {
    if (!dfg_node.HasDependency()) return false;
    absl::flat_hash_set<FieldPath> satisfied_fields =
        CollectSatisfiableFields(dfg_node, existing_nodes);
    // As long as we can satisfy any of the sink field, we consider it as
    // satisfiable.
    return !satisfied_fields.empty();
  }

  // Randomly selects a potential dependency for each dynamic field in `node`
  // and establishes the dependency between the node and the dependency source.
  // As we might have multiple calls to the same method in the existing graph
  // that can serve as the source, we randomly select one of them.
  void ConnectToExistingNodes(
      const absl::flat_hash_map<const google::protobuf::MethodDescriptor*,
                                std::vector<RpcNodeID>>
          existing_nodes,
      RpcNode& node, absl::BitGenRef prng) {
    const RpcPotentialDfgNode& dfg_node = abstract_dfg_.GetNode(node.method());

    // If we have multiple satisfiable field paths that are alternative to each
    // other (e.g., in the same `oneof`), we only need to pick one of them and
    // establish the concrete dependency.
    std::vector<FieldPath> satisfied_fields = RemoveAlternativeFieldPath(
        CollectSatisfiableFields(dfg_node, existing_nodes), prng);
    FUZZTEST_INTERNAL_CHECK(!satisfied_fields.empty(), "Impossible");
    for (const FieldPath& sink_field : satisfied_fields) {
      const auto& source_vec = dfg_node.GetDependencies(sink_field);
      std::vector<const RpcPotentialDfgNode::PotentialDependencySource*>
          satisfiable_sources;
      for (const RpcPotentialDfgNode::PotentialDependencySource& source :
           source_vec) {
        if (existing_nodes.contains(source.method))
          satisfiable_sources.push_back(&source);
      }
      if (satisfiable_sources.empty()) continue;
      FUZZTEST_INTERNAL_CHECK(!satisfiable_sources.empty(),
                              "Some dependencies are not satisified!");
      const RpcPotentialDfgNode::PotentialDependencySource& chosen_source =
          *PickRandomElement(satisfiable_sources, prng);
      const std::vector<RpcNodeID>& candidate_nodes =
          existing_nodes.find(chosen_source.method)->second;
      node.AddDependency(
          RpcDataFlowEdge{PickRandomElement(candidate_nodes, prng),
                          chosen_source.field_path, sink_field});
    }
  }

  // Inserts a tail call to the graph. Returns true if a call is inserted.
  bool InsertTailCall(corpus_type& graph, absl::BitGenRef prng) {
    absl::flat_hash_map<const google::protobuf::MethodDescriptor*, std::vector<RpcNodeID>>
        existing_nodes;
    RpcNodeID max_node_id = 0;
    for (const auto& [node_id, node] : graph.GetAllNodes()) {
      existing_nodes[&node.method()].push_back(node_id);
      max_node_id = std::max(max_node_id, node_id);
    }
    RpcNodeID new_node_id = max_node_id + 1;

    // Collect all the methods that can be inserted: They depend on existing
    // nodes and all their their dependencies can be satisfied by existing
    // nodes.
    std::vector<const google::protobuf::MethodDescriptor*> candidate_methods;
    for (auto& [method, unused_domain] : request_domains_) {
      const RpcPotentialDfgNode& dfg_node = abstract_dfg_.GetNode(*method);
      if (DependsOnAndCanBeSatisfiedBy(dfg_node, existing_nodes)) {
        candidate_methods.push_back(method);
      }
    }

    if (candidate_methods.empty()) return false;

    const google::protobuf::MethodDescriptor& method_to_insert =
        *PickRandomElement(candidate_methods, prng);
    auto& request_domain = GetRequestDomain(method_to_insert);
    RpcNode node_to_insert(method_to_insert,
                           request_domain.GetValue(request_domain.Init(prng)));
    ConnectToExistingNodes(existing_nodes, node_to_insert, prng);
    graph.AddNode(new_node_id, std::move(node_to_insert));
    return true;
  }

  bool DeleteTailCall(corpus_type& graph, absl::BitGenRef prng) {
    if (graph.NodeNum() == 1) return false;
    // Non-tail nodes (nodes with dependents).
    absl::flat_hash_set<RpcNodeID> non_tail_nodes;
    for (const auto& [node_id, node] : graph.GetAllNodes()) {
      for (const auto& edge : node.dependencies()) {
        non_tail_nodes.insert(edge.from_node_id);
      }
    }
    FUZZTEST_INTERNAL_CHECK(non_tail_nodes.size() != graph.NodeNum(),
                            "Loop dependence!");
    std::vector<RpcNodeID> tail_nodes;
    for (const auto& [node_id, node] : graph.GetAllNodes()) {
      if (!non_tail_nodes.contains(node_id)) tail_nodes.push_back(node_id);
    }

    graph.RemoveNode(PickRandomElement(tail_nodes, prng));
    return true;
  }

  bool MutateStaticField(corpus_type& graph, absl::BitGenRef prng,
                         bool only_shrink) {
    RpcNode& selected_node = std::next(graph.GetAllNodes().begin(),
                                       ChooseOffset(graph.NodeNum(), prng))
                                 ->second;
    auto& request_domain = GetRequestDomain(selected_node.method());
    auto request_domain_corpus_value =
        request_domain.FromValue(selected_node.request());
    FUZZTEST_INTERNAL_CHECK(request_domain_corpus_value.has_value(),
                            "Invalid proto!");
    request_domain.Mutate(*request_domain_corpus_value, prng, only_shrink);
    selected_node.request().CopyFrom(
        *request_domain.GetValue(*request_domain_corpus_value));
    return true;
  }

  ProtobufDomainUntypedImpl<google::protobuf::Message>& GetRequestDomain(
      const google::protobuf::MethodDescriptor& method) {
    auto iter = request_domains_.find(&method);
    FUZZTEST_INTERNAL_CHECK(iter != request_domains_.end(), "Invalid method!");
    return iter->second;
  }

  // We keep a domain for the request type for each method in the service to
  // generate the request message in the RpcNode.
  // TODO(changochen): We are now directly storing the concrete requests in
  // RpcNode, and serialize them as string. We should use the corpus_type of the
  // proto domain in the future to allow proto customization.
  absl::flat_hash_map<const google::protobuf::MethodDescriptor*,
                      ProtobufDomainUntypedImpl<google::protobuf::Message>>
      request_domains_;
  std::vector<const google::protobuf::MethodDescriptor*> all_methods_;
  RpcPotentialDataFlowGraph abstract_dfg_;
};
}  // namespace internal

using internal::RpcSequence;

inline absl::Status ExecuteRpcSequence(RpcStub& stub, RpcSequence& sequence) {
  return internal::RpcExecutor(&stub).Execute(sequence);
}

template <typename ServiceT>
inline auto RpcSession() {
  return internal::Lazy<internal::RpcSessionImpl<ServiceT>>();
}

// Creates an RpcSession with a service name factory. This is for when the
// service name is unknown at compile time (i.e., getting the name from the
// generated pool.). This factory function will be called after main().
// If the service name/type is known at compile time, please use the template
// version above: RpcSession<ServiceT>().
inline auto RpcSessionOf(
    std::function<absl::string_view()> service_name_factory) {
  FUZZTEST_INTERNAL_CHECK(service_name_factory, "Invalid service factory!");
  return internal::Lazy<internal::RpcSessionImpl<>,
                        std::function<absl::string_view()>>(
      std::move(service_name_factory));
}

}  // namespace fuzztest
#endif  // FUZZTEST_RPC_FUZZING_RPC_SESSION_H_
