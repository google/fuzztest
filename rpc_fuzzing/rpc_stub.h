#ifndef FUZZTEST_RPC_FUZZING_RPC_STUB_H_
#define FUZZTEST_RPC_FUZZING_RPC_STUB_H_

#include <memory>

#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"
#include "absl/status/statusor.h"

namespace fuzztest {

// RPC service stub interface.
class RpcStub {
 public:
  virtual ~RpcStub() = default;
  // Calls the RPC method described by `method_descriptor`, sending it `request`
  // and returning the obtained response.
  virtual absl::StatusOr<std::unique_ptr<google::protobuf::Message>> CallMethod(
      const google::protobuf::MethodDescriptor& method_descriptor,
      const google::protobuf::Message& request) = 0;
};

}  // namespace fuzztest

#endif  // FUZZTEST_RPC_FUZZING_RPC_STUB_H_
