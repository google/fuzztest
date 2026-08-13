// Copyright 2026 The Centipede Authors.
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

#include "./centipede/stop.h"

#include <atomic>
#include <cstdlib>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./centipede/thread_pool.h"

namespace fuzztest::internal {
namespace {

using ::testing::AllOf;
using ::testing::AnyOf;
using ::testing::Field;
using ::testing::StartsWith;

TEST(StopConditionTest, InitialState) {
  StopCondition stop_condition;
  EXPECT_FALSE(stop_condition.StopRequested());
  EXPECT_FALSE(stop_condition.ShouldStop());
  EXPECT_EQ(stop_condition.GetStopTime(), absl::InfiniteFuture());
}

TEST(StopConditionTest, RequestStopShortReason) {
  StopCondition stop_condition;
  stop_condition.RequestStop(EXIT_FAILURE, "test reason");

  EXPECT_TRUE(stop_condition.StopRequested());
  EXPECT_TRUE(stop_condition.ShouldStop());

  StopCondition::StopRequest request;
  EXPECT_TRUE(stop_condition.StopRequested(&request));
  EXPECT_EQ(request.exit_code, EXIT_FAILURE);
  EXPECT_EQ(request.reason, "test reason");
}

TEST(StopConditionTest, RequestStopLongReasonIsCapped) {
  StopCondition stop_condition;
  std::string long_reason(1000, 'a');
  stop_condition.RequestStop(EXIT_FAILURE, long_reason);

  StopCondition::StopRequest request;
  EXPECT_TRUE(stop_condition.StopRequested(&request));
  EXPECT_EQ(request.exit_code, EXIT_FAILURE);
  // 100 is a reasonable size to check.
  EXPECT_GE(request.reason.size(), 100);
  EXPECT_THAT(long_reason, StartsWith(request.reason));
}

TEST(StopConditionTest, RequestStopOnlyFirstCallTakesEffect) {
  StopCondition stop_condition;
  stop_condition.RequestStop(EXIT_FAILURE, "first reason");
  stop_condition.RequestStop(EXIT_SUCCESS, "second reason");

  StopCondition::StopRequest request;
  EXPECT_TRUE(stop_condition.StopRequested(&request));
  EXPECT_EQ(request.exit_code, EXIT_FAILURE);
  EXPECT_EQ(request.reason, "first reason");
}

TEST(StopConditionTest, ClearStopRequest) {
  StopCondition stop_condition;
  stop_condition.RequestStop(EXIT_FAILURE, "some reason");
  EXPECT_TRUE(stop_condition.StopRequested());

  stop_condition.ClearStopRequest();
  EXPECT_FALSE(stop_condition.StopRequested());

  StopCondition::StopRequest request;
  EXPECT_FALSE(stop_condition.StopRequested(&request));

  // Can request stop again after clearing
  stop_condition.RequestStop(EXIT_SUCCESS, "new reason");
  EXPECT_TRUE(stop_condition.StopRequested(&request));
  EXPECT_EQ(request.exit_code, EXIT_SUCCESS);
  EXPECT_EQ(request.reason, "new reason");
}

TEST(StopConditionTest, SetStopTime) {
  StopCondition stop_condition;
  absl::Time past_time = absl::Now() - absl::Seconds(10);
  stop_condition.SetStopTime(past_time);
  EXPECT_EQ(stop_condition.GetStopTime(), past_time);
  EXPECT_TRUE(stop_condition.ShouldStop());
  EXPECT_FALSE(stop_condition.StopRequested());
}

TEST(StopConditionTest, ConcurrentStopRequests) {
  StopCondition stop_condition;
  ThreadPool requesters(2);
  std::atomic<bool> stop_testing = false;
  requesters.Schedule([&] {
    while (!stop_testing) {
      stop_condition.RequestStop(/*exit_code=*/1234,
                                 "stop request from thread 1");
    }
  });
  requesters.Schedule([&] {
    while (!stop_testing) {
      stop_condition.RequestStop(/*exit_code=*/5678,
                                 "stop request from thread 2");
    }
  });
  bool got_stop_request_from_thread_1 = false;
  bool got_stop_request_from_thread_2 = false;
  const absl::Time start = absl::Now();
  while (absl::Now() - start < absl::Seconds(3)) {
    StopCondition::StopRequest stop_request;
    if (stop_condition.StopRequested(&stop_request)) {
      ASSERT_THAT(
          stop_request,
          AnyOf(AllOf(Field(&StopCondition::StopRequest::exit_code, 1234),
                      Field(&StopCondition::StopRequest::reason,
                            "stop request from thread 1")),
                AllOf(Field(&StopCondition::StopRequest::exit_code, 5678),
                      Field(&StopCondition::StopRequest::reason,
                            "stop request from thread 2"))));
      if (stop_request.exit_code == 1234) {
        got_stop_request_from_thread_1 = true;
      } else {
        got_stop_request_from_thread_2 = true;
      }
      stop_condition.ClearStopRequest();
    }
  }
  stop_testing = true;
  EXPECT_TRUE(got_stop_request_from_thread_1);
  EXPECT_TRUE(got_stop_request_from_thread_2);
  // Requester threads would be joined at the end, so if they got stuck the test
  // would time out.
}

}  // namespace
}  // namespace fuzztest::internal
