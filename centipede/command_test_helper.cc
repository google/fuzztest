// Copyright 2022 The Centipede Authors.
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

#include <cassert>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOGDI
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#endif

#include "absl/base/nullability.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"

// A binary linked with the fork server that exits/crashes in different ways.
int main(int argc, char** absl_nonnull argv) {
#if defined(_WIN32)
  // Disable the automatic \n -> \r\n conversion.
  _setmode(1, _O_BINARY);
#endif

  assert(argc >= 2);
  printf("Got input: %s\n", argv[1]);

  if (!strcmp(argv[1], "echo_args")) {
    for (int i = 2; i < argc; ++i) {
      printf("arg[%d]=%s\n", i - 2, argv[i]);
    }
    fflush(stdout);
    return EXIT_SUCCESS;
  }

  if (!strcmp(argv[1], "echo_env")) {
    for (int i = 2; i < argc; ++i) {
      const char* val = getenv(argv[i]);
      printf("%s=%s\n", argv[i], val ? val : "<UNSET>");
    }
    fflush(stdout);
    return EXIT_SUCCESS;
  }

  if (!strcmp(argv[1], "echo_stdin")) {
    char buf[1024];
    while (fgets(buf, sizeof(buf), stdin)) {
      fputs(buf, stdout);
    }
    fflush(stdout);
    return EXIT_SUCCESS;
  }

  fflush(stdout);

  if (!strcmp(argv[1], "success")) return EXIT_SUCCESS;
  if (!strcmp(argv[1], "fail")) return EXIT_FAILURE;

  int ret_code = 0;
  if (absl::StartsWith(argv[1], "ret") &&
      absl::SimpleAtoi(argv[1] + 3, &ret_code)) {
    return ret_code;
  }

  if (!strcmp(argv[1], "abort")) abort();
  if (!strcmp(argv[1], "ctrlc")) {
#if defined(_WIN32)
    SetConsoleCtrlHandler(NULL, FALSE);
    GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
    Sleep(INFINITE);
#else
    raise(SIGINT);
#endif
    return EXIT_SUCCESS;
  }
  // Sleep longer than kTimeout in CommandDeathTest_ForkServerHangingBinary.
  if (!strcmp(argv[1], "sleep")) absl::SleepFor(absl::Seconds(5));
  if (!strcmp(argv[1], "hang")) {
#if !defined(_WIN32)
    struct sigaction act{};
    act.sa_handler = [](int) {};
    sigaction(SIGTERM, &act, nullptr);
#endif
    absl::SleepFor(absl::Seconds(10));
  }

  return 17;
}
