// A grpc server that can run locally for testing.
#include <cstdint>
#include <memory>
#include <string>

#include "base/init_google.h"
#include "absl/base/log_severity.h"
#include "absl/flags/flag.h"
#include "absl/log/globals.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "./rpc_fuzzing/testdata/grpc/mini_blogger_service.h"
#include "grpcpp//security/server_credentials.h"
#include "grpcpp//server.h"
#include "grpcpp//server_builder.h"

ABSL_FLAG(int32_t, port, 5000, "port to listen on");

int main(int argc, char** argv) {
  InitGoogle(argv[0], &argc, &argv, /*remove_flags=*/true);

  absl::SetStderrThreshold(absl::LogSeverityAtLeast::kInfo);

  std::string server_address = absl::StrCat("[::]:", absl::GetFlag(FLAGS_port));

  fuzztest::internal::MiniBloggerGrpcService mini_blogger;
  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&mini_blogger);
  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
  LOG(INFO) << "Server listening on " << server_address;

  server->Wait();

  return 0;
}
