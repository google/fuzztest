#include "./rpc_fuzzing/scaffolding_stub.h"

#include <memory>
#include <string>

#include "net/base/sslconstant.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"
#include "net/rpc/anonymous-stub.h"
#include "net/rpc2/rpc2.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"

namespace fuzztest {

absl::StatusOr<std::unique_ptr<google::protobuf::Message>> ScaffoldingStub::CallMethod(
    const google::protobuf::MethodDescriptor& method_descriptor,
    const google::protobuf::Message& request) {
  const google::protobuf::Message* response_prototype =
      google::protobuf::MessageFactory::generated_factory()->GetPrototype(
          method_descriptor.output_type());
  if (!response_prototype) {
    return absl::InternalError(
        absl::StrCat("Cannot find prototype for ",
                     method_descriptor.output_type()->full_name(),
                     " in the generated proto MessageFactory"));
  }
  std::unique_ptr<google::protobuf::Message> response =
      absl::WrapUnique(response_prototype->New());
  if (!response) {
    return absl::InternalError(
        absl::StrCat("Cannot create a new instance of response type ",
                     method_descriptor.output_type()->full_name()));
  }

  RPC rpc;
  // AnonymousStub doesn't have access to the method options, so we need to set
  // this manually.
  if (method_descriptor.options().has_security_level()) {
    rpc.set_requested_security_level(net_base::SSLSecurityLevel(
        method_descriptor.options().security_level()));
  }
  const google::protobuf::ServiceDescriptor& service_descriptor =
      *method_descriptor.service();
  const std::string method_name = absl::StrCat("/", service_descriptor.name(),
                                               ".", method_descriptor.name());
  stub_->Send(/*package_name=*/"", method_name, &rpc, &request, response.get(),
              /* done= */ nullptr);
  rpc.WaitRespectingFiberCancellation();
  if (rpc.util_status().ok()) {
    return response;
  }
  return rpc.util_status();
}

}  // namespace fuzztest
