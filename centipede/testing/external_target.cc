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

#include <cstdint>
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const char* port_env = getenv("TARGET_PORT");
  int port = 0;
  CHECK(port_env && absl::SimpleAtoi(port_env, &port))
      << "env TARGET_PORT is not a number";

  int conn_sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  CHECK(conn_sock >= 0) << "Cannot create external runner socket";
  struct sockaddr_in server_addr;
  std::memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  server_addr.sin_port = htons(port);
  const int connect_result =
      connect(conn_sock, reinterpret_cast<sockaddr*>(&server_addr),
              sizeof(server_addr));
  if (connect_result != 0) return -1;
  const int enable_nodelay = 1;
  setsockopt(conn_sock, SOL_TCP, TCP_NODELAY, &enable_nodelay,
             sizeof(enable_nodelay));
  const uint64_t data_size = size;
  sendall(conn_sock, reinterpret_cast<const uint8_t*>(&data_size),
          sizeof(data_size));
  sendall(conn_sock, data, data_size);
  int match_result = 0;
  recvall(conn_sock, reinterpret_cast<uint8_t*>(&match_result),
          sizeof(match_result));
  CHECK_EQ(match_result, 0);
  uint64_t execution_result_size = 0;
  constexpr size_t kExecutionResultBufSize = 1 << 28;
  static uint8_t* execution_result_buf = new uint8_t[kExecutionResultBufSize];
  recvall(conn_sock, reinterpret_cast<uint8_t*>(&execution_result_size),
          sizeof(execution_result_size));
  CHECK(execution_result_size <= kExecutionResultBufSize);
  recvall(conn_sock, execution_result_buf, execution_result_size);
  shutdown(conn_sock, SHUT_RDWR);
  close(conn_sock);

  CentipedeSetExecutionResult(execution_result_buf, execution_result_size);

  return 0;
}
