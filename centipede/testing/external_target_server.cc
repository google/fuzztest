// Copyright 2024 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "absl/log/check.h"
#include "absl/strings/numbers.h"
#include "./centipede/runner_interface.h"

static void recvall(int sock, uint8_t* data, size_t size) {
  while (size > 0) {
    ssize_t recv_bytes = recv(sock, data, size, /*flags=*/0);
    CHECK(recv_bytes > 0 && recv_bytes <= size);
    data += recv_bytes;
    size -= recv_bytes;
  }
}

static void sendall(int sock, const uint8_t* data, size_t size) {
  while (size > 0) {
    ssize_t sent = send(sock, data, size, /*flags=*/0);
    CHECK(sent > 0 && sent <= size);
    data += sent;
    size -= sent;
  }
}

__attribute__((optnone)) int MatchSecret(const char* input,
                                         const char* secret) {
  if (std::strcmp(input, secret) == 0) {
    return 1;
  }
  return 0;
}

int main() {
  const char* port_env = getenv("TARGET_PORT");
  int port = 0;
  CHECK(port_env && absl::SimpleAtoi(port_env, &port))
      << "env TARGET_PORT is not a number";

  const int server_sock = socket(AF_INET, SOCK_STREAM, 0);
  CHECK(server_sock >= 0) << "Failed to create server socket";
  sockaddr_in server_addr;
  std::memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(port);

  if (bind(server_sock, reinterpret_cast<const sockaddr*>(&server_addr),
           sizeof(server_addr)) != 0) {
    CHECK(false) << "Failed to bind the server socket";
  }

  if (listen(server_sock, /*backlog=*/2) != 0) {
    CHECK(false) << "Failed to listen on the server socket";
  }

  static constexpr size_t kExecutionResultBufSize = 256 << 20;
  uint8_t* execution_result_buf = new uint8_t[kExecutionResultBufSize];

  CentipedeBeginExecutionBatch();
  fprintf(stderr, "external_target_server running\n");
  while (true) {
    sockaddr_in unused_conn_addr;
    socklen_t unused_conn_addr_len;
    const int conn_sock =
        accept(server_sock, reinterpret_cast<sockaddr*>(&unused_conn_addr),
               (unused_conn_addr_len = sizeof(unused_conn_addr_len),
                &unused_conn_addr_len));
    CHECK(conn_sock >= 0)
        << "Failed to accept connections from the server socket";
    const int enable_nodelay = 1;
    setsockopt(conn_sock, SOL_TCP, TCP_NODELAY, &enable_nodelay,
               sizeof(enable_nodelay));
    const char secret[] = "Secret";
    char buf[sizeof(secret)];

    CentipedePrepareProcessing();
    uint64_t input_size = 0;
    recvall(conn_sock, reinterpret_cast<uint8_t*>(&input_size),
            sizeof(input_size));
    recvall(conn_sock, reinterpret_cast<uint8_t*>(buf),
            std::min(sizeof(buf) - 1, input_size));
    buf[sizeof(buf) - 1] = 0;
    const int match_result = MatchSecret(buf, secret);
    CentipedeFinalizeProcessing();

    sendall(conn_sock, reinterpret_cast<const uint8_t*>(&match_result),
            sizeof(match_result));
    const uint64_t execution_result_size = CentipedeGetExecutionResult(
        execution_result_buf, kExecutionResultBufSize);
    sendall(conn_sock, reinterpret_cast<const uint8_t*>(&execution_result_size),
            sizeof(execution_result_size));
    sendall(conn_sock, execution_result_buf, execution_result_size);

    shutdown(conn_sock, SHUT_RDWR);
    close(conn_sock);
  }
  CentipedeEndExecutionBatch();

  delete[] execution_result_buf;
  fprintf(stderr, "external_target_server exiting\n");
  return 0;
}
