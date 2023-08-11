#include "./rpc_fuzzing/grpc_stub.h"

#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/notification.h"
#include "grpcpp//impl/proto_utils.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"
#include "grpcpp//client_context.h"
#include "grpcpp//generic/generic_stub.h"
#include "grpcpp//support/status.h"
#include "grpcpp//support/stub_options.h"

namespace fuzztest {

absl::StatusOr<std::unique_ptr<google::protobuf::Message>> GrpcStub::CallMethod(
    const google::protobuf::MethodDescriptor& method_descriptor,
    const google::protobuf::Message& request) {
  grpc::ClientContext cli_ctx;
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
  absl::Notification notification;
  absl::Status status = absl::OkStatus();
  grpc_stub_->UnaryCall(
      &cli_ctx,
      absl::StrCat("/", method_descriptor.service()->full_name(), "/",
                   method_descriptor.name()),
      grpc::StubOptions(), &request, response.get(),
      [&notification, &status](grpc::Status s) {
        // TODO(changochen): Better conversion from grpc::Status to absl::Status.
        if (!s.ok()) {
          status = absl::InternalError(s.error_message());
        }
        notification.Notify();
      });
  notification.WaitForNotification();
  if (status.ok()) {
    return response;
  } else {
    return status;
  }
}

}  // namespace fuzztest
