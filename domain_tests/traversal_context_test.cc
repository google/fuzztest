// Copyright 2026 Google LLC
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

#include "./fuzztest/internal/domains/traversal_context.h"

#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"

namespace fuzztest {
namespace {

using ::fuzztest::internal::TraversalCheckpoint;
using ::fuzztest::internal::TraversalContext;
using ::fuzztest::internal::TraversalContextWithTotalCount;
using ::fuzztest::internal::TraversalState;

struct TestDomain {};
struct AnotherTestDomain {};

TEST(TraversalContextTest, DepthTrackingDecrementsAndRestores) {
  TraversalState state;
  state.depth = 2;

  EXPECT_TRUE(state.status.ok());
  EXPECT_EQ(state.depth, 2);

  {
    TraversalContext<TestDomain> ctx1(state);
    EXPECT_EQ(state.depth, 1);
    EXPECT_FALSE(ctx1.IsResourceExhausted());

    {
      TraversalContext<TestDomain> ctx2(ctx1);
      EXPECT_EQ(state.depth, 0);
      EXPECT_FALSE(ctx2.IsResourceExhausted());

      {
        TraversalContext<TestDomain> ctx3(ctx2);
        EXPECT_EQ(state.depth, -1);
        EXPECT_TRUE(ctx3.IsResourceExhausted());
      }
      EXPECT_EQ(state.depth, 0);
    }
    EXPECT_EQ(state.depth, 1);
  }
  EXPECT_EQ(state.depth, 2);
}

TEST(TraversalContextTest, CountTrackingDecrementsAndDoesNotRestore) {
  TraversalState state;
  state.count = 2;

  {
    TraversalContextWithTotalCount<TestDomain> ctx1(state);
    EXPECT_EQ(*state.count, 1);
    EXPECT_FALSE(ctx1.IsResourceExhausted());

    {
      TraversalContextWithTotalCount<TestDomain> ctx2(ctx1);
      EXPECT_EQ(*state.count, 0);
      EXPECT_FALSE(ctx2.IsResourceExhausted());

      {
        TraversalContextWithTotalCount<TestDomain> ctx3(ctx2);
        EXPECT_EQ(*state.count, -1);
        EXPECT_TRUE(ctx3.IsResourceExhausted());
      }
    }
  }

  EXPECT_TRUE(state.count.has_value());
  EXPECT_EQ(*state.count, -1);
}

TEST(TraversalContextTest, CheckpointAndRestore) {
  TraversalState state;
  state.depth = 5;
  state.count = 5;

  TraversalContextWithTotalCount<TestDomain> ctx(state);
  EXPECT_EQ(state.depth, 4);
  EXPECT_EQ(*state.count, 4);

  TraversalCheckpoint cp = ctx.Checkpoint();

  {
    TraversalContextWithTotalCount<TestDomain> ctx1(ctx);   // depth 3, count 3
    TraversalContextWithTotalCount<TestDomain> ctx2(ctx1);  // depth 2, count 2
    state.status = absl::ResourceExhaustedError("Forced failure");
    EXPECT_FALSE(state.status.ok());
  }

  EXPECT_EQ(state.depth, 4);
  EXPECT_EQ(*state.count, 2);
  EXPECT_FALSE(state.status.ok());

  ctx.Restore(cp);

  EXPECT_TRUE(state.status.ok());
  EXPECT_EQ(state.depth, 4);
  EXPECT_EQ(*state.count, 4);
}

TEST(TraversalContextTest, ExhaustedContextFailsOnlyOnExplicitFail) {
  TraversalState state;
  state.depth = 0;  // Next enter will exhaust it

  TraversalContextWithTotalCount<TestDomain> ctx(state);  // depth -1
  EXPECT_TRUE(ctx.IsResourceExhausted());
  EXPECT_FALSE(ctx.IsFailed());

  // We can choose to fail:
  ctx.Fail();
  EXPECT_TRUE(ctx.IsFailed());
  EXPECT_FALSE(state.status.ok());
  EXPECT_THAT(state.status.ToString(),
              testing::HasSubstr("Traversal budget exceeded"));
}

TEST(TraversalContextTest, ExistingCountIsNotReset) {
  TraversalState state;
  // Initially count is nullopt.
  EXPECT_FALSE(state.count.has_value());

  {
    TraversalContextWithTotalCount<TestDomain> ctx1(state);
    // Root context initializes count to kDefaultMaxCount because it was
    // nullopt.
    EXPECT_TRUE(state.count.has_value());
    // Decremented during Enter()
    EXPECT_EQ(*state.count, 999);

    {
      // Copy to another domain type.
      TraversalContextWithTotalCount<AnotherTestDomain> ctx2(ctx1);
      EXPECT_EQ(*state.count, 998);  // Decremented during ctx2's Enter()
    }
    // ctx2 destructed. Since it is a copy, it should NOT reset state.count to
    // nullopt.

    EXPECT_TRUE(state.count.has_value());
    EXPECT_EQ(*state.count, 998);
  }
  // ctx1 destructed. Since it is the root, it SHOULD reset state.count to
  // nullopt.

  EXPECT_FALSE(state.count.has_value());
}
TEST(TraversalContextTest, NewCountIsInitializedAndReset) {
  TraversalState state;
  state.depth = 5;

  TraversalContext<TestDomain> ctx_without_count(state);
  EXPECT_EQ(state.depth, 4);
  EXPECT_FALSE(state.count.has_value());

  {
    // Construct TraversalContextWithTotalCount from TraversalContext.
    // It should initialize the count.
    TraversalContextWithTotalCount<AnotherTestDomain> ctx_with_count(
        ctx_without_count);
    EXPECT_EQ(state.depth, 3);
    EXPECT_TRUE(state.count.has_value());
    // Decremented in InitCount() from the max value of 1000.
    EXPECT_EQ(*state.count, 999);
  }  // ctx_with_count destructed. It should reset count to nullopt.

  EXPECT_EQ(state.depth, 4);
  EXPECT_FALSE(state.count.has_value());
}

struct ExhaustionTestParam {
  TraversalState state;
  bool expected_exhausted;
  bool expected_failed;
};

class TraversalContextExhaustionTest
    : public testing::TestWithParam<ExhaustionTestParam> {};

TEST_P(TraversalContextExhaustionTest, ChecksIsResourceExhaustedAndIsFailed) {
  const auto& param = GetParam();
  TraversalState state = param.state;
  TraversalContextWithTotalCount<TestDomain> ctx(state);
  EXPECT_EQ(ctx.IsResourceExhausted(), param.expected_exhausted);
  EXPECT_EQ(ctx.IsFailed(), param.expected_failed);
}

INSTANTIATE_TEST_SUITE_P(
    TraversalContextTests, TraversalContextExhaustionTest,
    testing::Values(ExhaustionTestParam{TraversalState{1, 1}, false, false},
                    ExhaustionTestParam{TraversalState{0, std::nullopt}, true,
                                        false},
                    ExhaustionTestParam{TraversalState{1, 0}, true, false},
                    ExhaustionTestParam{
                        TraversalState{1, 1, absl::CancelledError("cancelled")},
                        false, true}));

TEST(TraversalContextTest, ErrorTraceAccumulatesOnUnwinding) {
  TraversalState state;
  struct DomainC {};
  struct DomainB {};
  struct DomainA {};

  {
    TraversalContext<DomainA> ctxA(state);
    {
      TraversalContext<DomainB> ctxB(ctxA);
      {
        TraversalContext<DomainC> ctxC(ctxB);
        ctxC.Fail();
      }
    }
  }

  EXPECT_FALSE(state.status.ok());
  EXPECT_THAT(state.error_trace,
              testing::ElementsAre(testing::HasSubstr("DomainC"),
                                   testing::HasSubstr("DomainB"),
                                   testing::HasSubstr("DomainA")));
}

TEST(TraversalContextTest, DepthCappedAtMinusOne) {
  TraversalState state;
  state.depth = 1;

  {
    // depth 0
    TraversalContext<TestDomain> ctx1(state);
    EXPECT_EQ(state.depth, 0);
    {
      // depth -1
      TraversalContext<TestDomain> ctx2(ctx1);
      EXPECT_EQ(state.depth, -1);
      {
        // depth capped at -1
        TraversalContext<TestDomain> ctx3(ctx2);
        EXPECT_EQ(state.depth, -1);
      }  // exit ctx3 -> depth stays -1
      EXPECT_EQ(state.depth, -1);
    }  // exit ctx2 -> depth becomes 0
    EXPECT_EQ(state.depth, 0);
  }  // exit ctx1 -> depth becomes 1
  EXPECT_EQ(state.depth, 1);
}

TEST(TraversalContextTest, CountCappedAtMinusOne) {
  TraversalState state;
  state.count = 1;

  {
    TraversalContextWithTotalCount<TestDomain> ctx(state);
    EXPECT_EQ(*state.count, 0);
  }
  {
    TraversalContextWithTotalCount<TestDomain> ctx(state);
    EXPECT_EQ(*state.count, -1);
  }
  {
    TraversalContextWithTotalCount<TestDomain> ctx(state);
    EXPECT_EQ(*state.count, -1);
  }
}

}  // namespace
}  // namespace fuzztest
