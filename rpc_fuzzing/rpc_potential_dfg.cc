#include "./rpc_fuzzing/rpc_potential_dfg.h"

#include <vector>

#include "google/protobuf/descriptor.h"
#include "./fuzztest/internal/logging.h"
#include "./rpc_fuzzing/proto_field_path.h"

namespace fuzztest::internal {

namespace {

// Get the type name of a field. If it is a message type, then return its
// concrete message type name.
std::string_view GetTypeNameForField(const google::protobuf::FieldDescriptor& field) {
  if (field.type() == google::protobuf::FieldDescriptor::TYPE_MESSAGE) {
    return field.message_type()->name();
  } else {
    return field.type_name();
  }
}

// Describe a field path in a specific method's request or response.
struct DetailedFieldInfo {
  // Use pointer to keep it copy assignable.
  const google::protobuf::MethodDescriptor* method;
  bool in_request;
  FieldPath field_path;
};

// Collect either all the fields in the response/request of a method.
std::vector<DetailedFieldInfo> CollectFieldInfoInMethod(
    const google::protobuf::MethodDescriptor& method, bool collect_request) {
  const google::protobuf::Descriptor& message_descriptor =
      collect_request ? *method.input_type() : *method.output_type();
  std::vector<FieldPath> all_field_paths = CollectAllFields(message_descriptor);
  std::vector<DetailedFieldInfo> result;
  result.reserve(all_field_paths.size());
  for (const auto& field_path : all_field_paths) {
    result.push_back(DetailedFieldInfo{&method, collect_request, field_path});
  }
  return result;
}

std::vector<DetailedFieldInfo> CollectDefinitions(
    const google::protobuf::MethodDescriptor& method) {
  return CollectFieldInfoInMethod(method, /*collect_request=*/false);
}

std::vector<DetailedFieldInfo> CollectUses(
    const google::protobuf::MethodDescriptor& method) {
  return CollectFieldInfoInMethod(method, /*collect_request=*/true);
}

bool InSameMethod(const DetailedFieldInfo& a, const DetailedFieldInfo& b) {
  return a.method->full_name() == b.method->full_name();
}

bool HasSameNameAndType(const DetailedFieldInfo& a,
                        const DetailedFieldInfo& b) {
  const google::protobuf::FieldDescriptor& a_field = a.field_path.GetLastField();
  const google::protobuf::FieldDescriptor& b_field = b.field_path.GetLastField();
  return a_field.name() == b_field.name() &&
         GetTypeNameForField(a_field) == GetTypeNameForField(b_field);
}

}  // namespace

void RpcPotentialDfgNode::AddDependency(
    const google::protobuf::MethodDescriptor& source_method,
    const FieldPath& source_field, const FieldPath& sink_field) {
  dependencies_[sink_field].push_back(
      PotentialDependencySource{&source_method, source_field});
}

void RpcPotentialDataFlowGraph::AddDependency(
    const google::protobuf::MethodDescriptor& source_method,
    const FieldPath& source_field, const google::protobuf::MethodDescriptor& sink_method,
    const FieldPath& sink_field) {
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(
      nodes_.find(&source_method) != nodes_.end(), "No such source method!");
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(
      nodes_.find(&sink_method) != nodes_.end(), "No such sink method!");
  RpcPotentialDfgNode& sink_node = nodes_.find(&sink_method)->second;
  sink_node.AddDependency(source_method, source_field, sink_field);
}

RpcPotentialDataFlowGraph::RpcPotentialDataFlowGraph(
    const google::protobuf::ServiceDescriptor& service) {
  for (int i = 0; i < service.method_count(); ++i) {
    const google::protobuf::MethodDescriptor& method = *service.method(i);
    nodes_.emplace(&method, RpcPotentialDfgNode(method));
  }
}

RpcPotentialDataFlowGraph RpcPotentialDataFlowGraph::Create(
    const google::protobuf::ServiceDescriptor& service_descriptor) {
  // Collect all the definitions and uses.
  std::vector<DetailedFieldInfo> all_definitions, all_uses;
  for (int i = 0; i < service_descriptor.method_count(); ++i) {
    const google::protobuf::MethodDescriptor& method = *service_descriptor.method(i);
    std::vector<DetailedFieldInfo> definitions = CollectDefinitions(method);
    std::vector<DetailedFieldInfo> uses = CollectUses(method);
    all_definitions.insert(all_definitions.end(), definitions.begin(),
                           definitions.end());
    all_uses.insert(all_uses.end(), uses.begin(), uses.end());
  }

  // For each pair of definition and use with same name and type, add a
  // dependency (edge) in the graph.
  RpcPotentialDataFlowGraph graph(service_descriptor);
  for (const DetailedFieldInfo& define_field_info : all_definitions) {
    for (const DetailedFieldInfo& use_field_info : all_uses) {
      if (!InSameMethod(define_field_info, use_field_info) &&
          HasSameNameAndType(define_field_info, use_field_info)) {
        graph.AddDependency(*define_field_info.method,
                            define_field_info.field_path,
                            *use_field_info.method, use_field_info.field_path);
      }
    }
  }
  return graph;
}

const std::vector<RpcPotentialDfgNode::PotentialDependencySource>&
RpcPotentialDfgNode::GetDependencies(const FieldPath& sink) const {
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(
      dependencies_.find(sink) != dependencies_.end(), "No such sink!");
  return dependencies_.at(sink);
}

const RpcPotentialDfgNode& RpcPotentialDataFlowGraph::GetNode(
    const google::protobuf::MethodDescriptor& method) const {
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(nodes_.find(&method) != nodes_.end(),
                                       "No such method!");
  return nodes_.at(&method);
}

const google::protobuf::ServiceDescriptor& GetServiceDescriptorByServiceName(
    absl::string_view service_name) {
  const google::protobuf::ServiceDescriptor* service =
      google::protobuf::DescriptorPool::generated_pool()->FindServiceByName(
          service_name.data());
  FUZZTEST_INTERNAL_CHECK(service != nullptr,
                          std::string(service_name) + " Service not found!");
  return *service;
}

RpcPotentialDataFlowGraph CreatePotentialDfgByServiceName(
    absl::string_view service_name) {
  return RpcPotentialDataFlowGraph::Create(
      GetServiceDescriptorByServiceName(service_name));
}

}  // namespace fuzztest::internal
