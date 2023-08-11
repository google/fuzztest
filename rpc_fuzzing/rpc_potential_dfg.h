#ifndef FUZZTEST_RPC_FUZZING_RPC_POTENTIAL_DFG_H_
#define FUZZTEST_RPC_FUZZING_RPC_POTENTIAL_DFG_H_

#include <type_traits>
#include <vector>

#include "google/protobuf/descriptor.h"
#include "google/protobuf/service.h"
#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/internal/logging.h"
#include "./rpc_fuzzing/proto_field_path.h"

namespace fuzztest::internal {

// A `RpcPotentialDfgNode` describes the potential dependencies for the
// fields in a request of a rpc method.
class RpcPotentialDfgNode {
 public:
  RpcPotentialDfgNode(const google::protobuf::MethodDescriptor& method)
      : method_(method) {}

  // Establish a dependency from the `source_field` to the `sink_field` of
  // current method.
  void AddDependency(const google::protobuf::MethodDescriptor& source_method,
                     const FieldPath& source_field,
                     const FieldPath& sink_field);

  // Get the method representing by the node.
  const google::protobuf::MethodDescriptor& GetMethod() const { return method_; }

  // Source of dependency, which should be in the response of a method.
  struct PotentialDependencySource {
    // `method` will never be null. Use a pointer to keep it copy assignable.
    const google::protobuf::MethodDescriptor* method;
    FieldPath field_path;
  };

  const absl::flat_hash_map<FieldPath, std::vector<PotentialDependencySource>>&
  GetAllDependencies() const {
    return dependencies_;
  }

  const std::vector<PotentialDependencySource>& GetDependencies(
      const FieldPath& sink) const;
  bool HasDependency() const { return !dependencies_.empty(); }

 private:
  const google::protobuf::MethodDescriptor& method_;
  absl::flat_hash_map<FieldPath /*sink*/,
                      std::vector<PotentialDependencySource> /*source*/>
      dependencies_;
};

// A `RpcPotentialDataFlowGraph` describes all the potential dependencies among
// methods in a service. Each method is represented as a node in the graph.
class RpcPotentialDataFlowGraph {
 public:
  // Get the node representing `method`.
  const RpcPotentialDfgNode& GetNode(
      const google::protobuf::MethodDescriptor& method) const;

  // Create an `RpcPotentialDfg` with each method in the service being
  // a node, and add dependencies between the methods.
  static RpcPotentialDataFlowGraph Create(
      const google::protobuf::ServiceDescriptor& service);

 private:
  RpcPotentialDataFlowGraph(const google::protobuf::ServiceDescriptor& service);
  // Add a dependency on the field from the response of `source_method` to the
  // request of `sink_method`.
  void AddDependency(const google::protobuf::MethodDescriptor& source_method,
                     const FieldPath& source_field,
                     const google::protobuf::MethodDescriptor& sink_method,
                     const FieldPath& sink_field);

  absl::flat_hash_map<const google::protobuf::MethodDescriptor*, RpcPotentialDfgNode>
      nodes_;
};

template <typename T, typename = void>
struct is_stubby_service : std::false_type {};

template <typename ServiceT>
struct is_stubby_service<ServiceT, std::void_t<decltype(ServiceT::descriptor)>>
    : std::true_type {};

template <typename T, typename = void>
struct is_grpc_service : std::false_type {};

template <typename ServiceT>
struct is_grpc_service<ServiceT,
                       std::void_t<decltype(ServiceT::service_full_name)>>
    : std::true_type {};

// Get the service descriptor based on the service type. Currently support
// protobuf services and stubby services.
template <typename ServiceT>
const google::protobuf::ServiceDescriptor& GetServiceDescriptor() {
  if constexpr (std::is_same_v<ServiceT, google::protobuf::Service>) {
    return *ServiceT::descriptor();
  } else if constexpr (is_stubby_service<ServiceT>::value) {
    return *google::protobuf::DescriptorPool::generated_pool()->FindServiceByName(
        ServiceT::descriptor.full_name());
  } else if constexpr (is_grpc_service<ServiceT>::value) {
    return *google::protobuf::DescriptorPool::generated_pool()->FindServiceByName(
        ServiceT::service_full_name());
  } else {
    FUZZTEST_INTERNAL_CHECK(false, "Unsupported service type!");
  }
}

// Get the service descriptor based on the fully qualified service name such as
// "package.ServiceName".
const google::protobuf::ServiceDescriptor& GetServiceDescriptorByServiceName(
    absl::string_view service_name);

// Create an potential data flow graph for a service type.
template <typename ServiceT>
RpcPotentialDataFlowGraph CreatePotentialDfg() {
  return RpcPotentialDataFlowGraph::Create(GetServiceDescriptor<ServiceT>());
}

RpcPotentialDataFlowGraph CreatePotentialDfgByServiceName(
    absl::string_view service_name);

}  // namespace fuzztest::internal

#endif  // FUZZTEST_RPC_FUZZING_RPC_POTENTIAL_DFG_H_
