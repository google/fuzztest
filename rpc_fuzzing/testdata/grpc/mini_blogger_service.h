#ifndef FUZZTEST_RPC_FUZZING_TESTDATA_MINI_BLOGGER_GRPC_SERVICE_H_
#define FUZZTEST_RPC_FUZZING_TESTDATA_MINI_BLOGGER_GRPC_SERVICE_H_

#include "./rpc_fuzzing/testdata/mini_blogger.grpc.pb.h"
#include "./rpc_fuzzing/testdata/mini_blogger.pb.h"
#include "./rpc_fuzzing/testdata/mini_blogger_context.h"
#include "grpcpp//support/status.h"

namespace fuzztest::internal {

// The gRpc server implementation of MiniBlogger.
class MiniBloggerGrpcService : public MiniBlogger::Service {
 public:
  grpc::Status RegisterUser(grpc::ServerContext*,
                            const RegisterUserRequest* request,
                            RegisterUserResponse* response) override;

  grpc::Status LogInUser(grpc::ServerContext*, const LogInUserRequest* request,
                         LogInUserResponse* response) override;

  grpc::Status GetUserPosts(grpc::ServerContext*,
                            const GetUserPostsRequest* request,
                            GetUserPostsResponse* response) override;

  grpc::Status LogOutUser(grpc::ServerContext*,
                          const LogOutUserRequest* request,
                          LogOutUserResponse* response) override;

 private:
  MiniBloggerContext mini_blogger_context_;
};
}  // namespace fuzztest::internal

#endif  // FUZZTEST_RPC_FUZZING_TESTDATA_MINI_BLOGGER_GRPC_SERVICE_H_
