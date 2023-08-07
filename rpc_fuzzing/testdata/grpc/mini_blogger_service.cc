#include "./rpc_fuzzing/testdata/grpc/mini_blogger_service.h"

#include "./rpc_fuzzing/testdata/mini_blogger.pb.h"
#include "grpcpp//server_context.h"
#include "grpcpp//support/status.h"

namespace fuzztest::internal {

grpc::Status MiniBloggerGrpcService::RegisterUser(
    grpc::ServerContext*, const RegisterUserRequest* request,
    RegisterUserResponse* response) {
  mini_blogger_context_.RegisterUser(*request, *response);
  return grpc::Status::OK;
}

grpc::Status MiniBloggerGrpcService::LogInUser(grpc::ServerContext*,
                                               const LogInUserRequest* request,
                                               LogInUserResponse* response) {
  mini_blogger_context_.LogInUser(*request, *response);
  return grpc::Status::OK;
}

grpc::Status MiniBloggerGrpcService::GetUserPosts(
    grpc::ServerContext* unused_service_context,
    const GetUserPostsRequest* request, GetUserPostsResponse* response) {
  mini_blogger_context_.GetUserPosts(*request, *response);
  return grpc::Status::OK;
}

grpc::Status MiniBloggerGrpcService::LogOutUser(
    grpc::ServerContext* unused_service_context,
    const LogOutUserRequest* request, LogOutUserResponse* response) {
  mini_blogger_context_.LogOutUser(*request, *response);
  return grpc::Status::OK;
}
}  // namespace fuzztest::internal
