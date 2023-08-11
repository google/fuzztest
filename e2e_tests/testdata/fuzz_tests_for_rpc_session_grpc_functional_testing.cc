// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Rpc session fuzz test examples to be used for e2e functional testing.
//
// Specifically, used by `functional_test` only.

#include <cstdlib>
#include <iostream>
#include <memory>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/fuzztest.h"
#include "./rpc_fuzzing/grpc_stub.h"
#include "./rpc_fuzzing/rpc_session.h"
#include "./rpc_fuzzing/testdata/grpc/mini_blogger_service.h"
#include "./rpc_fuzzing/testdata/mini_blogger.grpc.pb.h"
#include "grpcpp//security/server_credentials.h"
#include "grpcpp//server.h"
#include "grpcpp//server_builder.h"
#include "grpcpp//support/channel_arguments.h"

namespace {

std::string_view ServiceNameFactory() {
  return "fuzztest.internal.MiniBlogger";
}

class MiniBloggerGrpcTest {
 public:
  MiniBloggerGrpcTest()
      : server_(grpc::ServerBuilder()
                    .RegisterService(&mini_blogger_service_)
                    .BuildAndStart()),
        stub_(server_->InProcessChannel(grpc::ChannelArguments())) {}

  ~MiniBloggerGrpcTest() { server_->Shutdown(); }

  void ServiceDoesNotCrashWithAnyRpcSequence(
      fuzztest::RpcSequence rpc_sequence) {
    absl::Status status = fuzztest::ExecuteRpcSequence(stub_, rpc_sequence);
    if (!status.ok()) {
      std::cerr << "Failed to execute !" << status.message() << "\n";
      std::abort();
    }
  }

  void TestRpcSessionOfSetup(fuzztest::RpcSequence rpc_sequence) {
    ServiceDoesNotCrashWithAnyRpcSequence(rpc_sequence);
  }

 private:
  fuzztest::internal::MiniBloggerGrpcService mini_blogger_service_;
  std::unique_ptr<grpc::Server> server_ = nullptr;
  fuzztest::GrpcStub stub_;
};

FUZZ_TEST_F(MiniBloggerGrpcTest, ServiceDoesNotCrashWithAnyRpcSequence)
    .WithDomains(fuzztest::RpcSession<fuzztest::internal::MiniBlogger>());

FUZZ_TEST_F(MiniBloggerGrpcTest, TestRpcSessionOfSetup)
    .WithDomains(fuzztest::RpcSessionOf(ServiceNameFactory));

}  // namespace
