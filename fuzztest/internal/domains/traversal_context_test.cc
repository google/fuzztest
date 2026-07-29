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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"

namespace fuzztest::domain_implementor {
namespace {

struct TestDomain {};
struct AnotherTestDomain {};

TEST(TraversalContextTest, DepthTrackingDecrementsAndRestores) {
  TraversalState state;
  state.depth_budget = 1;

  EXPECT_TRUE(state.status.ok());
  EXPECT_EQ(state.depth_budget, 1);

  {
    TraversalContext<TestDomain> ctx1(state);
    EXPECT_EQ(state.depth_budget, 0);
    EXPECT_FALSE(ctx1.IsResourceExhausted());

    {
      TraversalContext<TestDomain> ctx2(ctx1);
      EXPECT_EQ(state.depth_budget, -1);
      EXPECT_TRUE(ctx2.IsResourceExhausted());
    }
    EXPECT_EQ(state.depth_budget, 0);
  }
  EXPECT_EQ(state.depth_budget, 1);
}

TEST(TraversalContextTest, InitBudgetTrackingDecrementsAndDoesNotRestore) {
  TraversalState state;
  state.init_budget = 1;

  {
    InitTraversalContext<TestDomain> ctx1(state);
    EXPECT_EQ(state.init_budget, 0);
    EXPECT_FALSE(ctx1.IsResourceExhausted());

    {
      InitTraversalContext<TestDomain> ctx2(ctx1);
      EXPECT_EQ(state.init_budget, -1);
      EXPECT_TRUE(ctx2.IsResourceExhausted());
    }
  }

  EXPECT_EQ(state.init_budget, -1);
}

TEST(TraversalContextTest, MixedTraversalContextsInitBudgetTracking) {
  TraversalState state;
  state.init_budget = 2;

  {
    InitTraversalContext<TestDomain> ctx1(state);  // Init: decrements to 1
    EXPECT_EQ(state.init_budget, 1);

    {
      TraversalContext<TestDomain> ctx2(ctx1);  // Mutate: does NOT decrement
      EXPECT_EQ(state.init_budget, 1);

      {
        InitTraversalContext<TestDomain> ctx3(ctx2);  // Init: decrements to 0
        EXPECT_EQ(state.init_budget, 0);
      }
    }
  }
  EXPECT_EQ(state.init_budget, 0);
}

TEST(TraversalContextTest, ExhaustedContextFailsOnlyOnExplicitFail) {
  TraversalState state;
  state.depth_budget = 0;  // Next enter will exhaust it

  InitTraversalContext<TestDomain> ctx(state);  // depth -1
  EXPECT_TRUE(ctx.IsResourceExhausted());
  EXPECT_FALSE(ctx.IsFailed());

  // We can choose to fail:
  ctx.FailWithBudgetExceeded();
  EXPECT_TRUE(ctx.IsFailed());
  EXPECT_FALSE(state.status.ok());
  EXPECT_THAT(state.status.ToString(),
              testing::HasSubstr("Traversal budget exceeded"));
}

TEST(TraversalContextTest, ExistingInitBudgetIsNotReset) {
  TraversalState state;  // init_budget defaults to 1000
  EXPECT_EQ(state.init_budget, 1000);

  {
    InitTraversalContext<TestDomain> ctx1(state);
    EXPECT_EQ(state.init_budget, 999);

    {
      InitTraversalContext<AnotherTestDomain> ctx2(ctx1);
      EXPECT_EQ(state.init_budget, 998);
    }
    // ctx2 destructed. No change to init_budget.
    EXPECT_EQ(state.init_budget, 998);
  }
  // ctx1 destructed. No change to init_budget.
  EXPECT_EQ(state.init_budget, 998);
}

TEST(TraversalContextTest, TransitionToInitTraversalContext) {
  TraversalState state;  // init_budget = 1000, depth_budget = 100
  state.depth_budget = 5;

  TraversalContext<TestDomain> ctx_without_budget(state);
  EXPECT_EQ(state.depth_budget, 4);
  EXPECT_EQ(state.init_budget, 1000);  // Not decremented by TraversalContext

  {
    InitTraversalContext<AnotherTestDomain> ctx_with_budget(ctx_without_budget);
    EXPECT_EQ(state.depth_budget, 3);   // Decremented by TraversalContext base
    EXPECT_EQ(state.init_budget, 999);  // Decremented by InitTraversalContext
  }
  // ctx_with_budget destructed. depth_budget is restored, init_budget is NOT.
  EXPECT_EQ(state.depth_budget, 4);
  EXPECT_EQ(state.init_budget, 999);
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
  InitTraversalContext<TestDomain> ctx(state);
  EXPECT_EQ(ctx.IsResourceExhausted(), param.expected_exhausted);
  EXPECT_EQ(ctx.IsFailed(), param.expected_failed);
}

INSTANTIATE_TEST_SUITE_P(
    TraversalContextTests, TraversalContextExhaustionTest,
    testing::Values(ExhaustionTestParam{TraversalState{1, 1}, false, false},
                    ExhaustionTestParam{TraversalState{0, 1000}, true, false},
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
        ctxC.FailWithBudgetExceeded();
      }
    }
  }

  EXPECT_FALSE(state.status.ok());
  EXPECT_THAT(state.error_trace,
              testing::ElementsAre(testing::HasSubstr("DomainC"),
                                   testing::HasSubstr("DomainB"),
                                   testing::HasSubstr("DomainA")));
}

TEST(TraversalContextTest, DepthGoesBelowMinusOneAndRestores) {
  TraversalState state;
  state.depth_budget = 1;

  {
    // depth 0
    TraversalContext<TestDomain> ctx1(state);
    EXPECT_EQ(state.depth_budget, 0);
    {
      // depth -1
      TraversalContext<TestDomain> ctx2(ctx1);
      EXPECT_EQ(state.depth_budget, -1);
      {
        // depth goes to -2 (no longer capped)
        TraversalContext<TestDomain> ctx3(ctx2);
        EXPECT_EQ(state.depth_budget, -2);
      }  // exit ctx3 -> depth becomes -1
      EXPECT_EQ(state.depth_budget, -1);
    }  // exit ctx2 -> depth becomes 0
    EXPECT_EQ(state.depth_budget, 0);
  }  // exit ctx1 -> depth becomes 1
  EXPECT_EQ(state.depth_budget, 1);
}

TEST(TraversalContextTest, InitBudgetCappedAtMinusOne) {
  TraversalState state;
  state.init_budget = 1;

  {
    InitTraversalContext<TestDomain> ctx(state);
    EXPECT_EQ(state.init_budget, 0);
  }
  {
    InitTraversalContext<TestDomain> ctx(state);
    EXPECT_EQ(state.init_budget, -1);
  }
  {
    InitTraversalContext<TestDomain> ctx(state);
    EXPECT_EQ(state.init_budget, -1);
  }
}

TEST(TraversalContextTest, PassthroughDoesNotDecrementBudgets) {
  TraversalState state;
  state.depth_budget = 5;
  state.init_budget = 10;

  {
    InitTraversalContext<TestDomain> ctx(state);
    EXPECT_EQ(state.depth_budget, 4);
    EXPECT_EQ(state.init_budget, 9);

    {
      auto passthrough_ctx =
          InitTraversalContext<AnotherTestDomain>::Passthrough(ctx);
      EXPECT_EQ(state.depth_budget, 4);  // Not decremented
      EXPECT_EQ(state.init_budget, 9);   // Not decremented
    }
    // passthrough_ctx destructed. No change.
    EXPECT_EQ(state.depth_budget, 4);
    EXPECT_EQ(state.init_budget, 9);
  }
  // ctx destructed. depth_budget restored.
  EXPECT_EQ(state.depth_budget, 5);
  EXPECT_EQ(state.init_budget, 9);
}

TEST(TraversalContextTest, PassthroughDoesNotAddToErrorTrace) {
  TraversalState state;

  {
    InitTraversalContext<TestDomain> ctx(state);

    {
      auto passthrough_ctx =
          InitTraversalContext<AnotherTestDomain>::Passthrough(ctx);

      passthrough_ctx.FailWithBudgetExceeded();
      EXPECT_FALSE(state.status.ok());
    }
    // passthrough_ctx destructed. It should not add "AnotherTestDomain" to
    // error_trace.
    EXPECT_TRUE(state.error_trace.empty());
  }
  // ctx destructed. It was active (enter_ok_ is true).
  // So it should add "TestDomain" to error_trace because status is now not ok.
  EXPECT_THAT(state.error_trace, testing::ElementsAre("TestDomain"));
}

}  // namespace
}  // namespace fuzztest::domain_implementor
