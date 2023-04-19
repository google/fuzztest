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

#include "./centipede/logging.h"

#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/log/scoped_mock_log.h"

namespace centipede {
namespace {

using testing::_;

TEST(LoggingTest, Vlog) {
  absl::ScopedMockLog log;

  EXPECT_CALL(log, Log(absl::LogSeverity::kInfo, _, "VLOG(0)")).Times(1);
  EXPECT_CALL(log, Log(absl::LogSeverity::kInfo, _, "VLOG(5)")).Times(1);
  EXPECT_CALL(log, Log(absl::LogSeverity::kInfo, _, "VLOG(9)")).Times(1);
  EXPECT_CALL(log, Log(absl::LogSeverity::kInfo, _, "VLOG(10)")).Times(1);
  EXPECT_CALL(log, Log(absl::LogSeverity::kInfo, _, "VLOG(11)")).Times(0);

  log.StartCapturingLogs();  // Call this after done setting expectations.

  absl::SetFlag(&FLAGS_v, 10);
#define TEST_VLOG(level) VLOG(level) << "VLOG(" << level << ")"
  TEST_VLOG(0);
  TEST_VLOG(5);
  TEST_VLOG(9);
  TEST_VLOG(10);
  TEST_VLOG(11);
}

}  // namespace
}  // namespace centipede
