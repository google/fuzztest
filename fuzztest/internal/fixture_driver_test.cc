// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./fuzztest/internal/fixture_driver.h"

#include <string>
#include <tuple>
#include <type_traits>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/types/span.h"
#include "./fuzztest/domain.h"
#include "./fuzztest/internal/registration.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {
namespace {

using ::testing::IsEmpty;
using ::testing::UnorderedElementsAre;

struct CallCountFixture {
  void IncrementCallCount(int n) { call_count += n; }
  inline static int call_count;
};

using IncrementCallCountFunc = decltype(&CallCountFixture::IncrementCallCount);
using CallCountRegBase =
    DefaultRegistrationBase<CallCountFixture, IncrementCallCountFunc>;

template <typename... T>
MoveOnlyAny MakeArgs(T... t) {
  return MoveOnlyAny(std::in_place_type<std::tuple<T...>>, std::tuple(t...));
}

TEST(FixtureDriverTest, PropagatesCallToTargetFunction) {
  FixtureDriverImpl<Domain<std::tuple<int>>, CallCountFixture,
                    IncrementCallCountFunc>
      fixture_driver(&CallCountFixture::IncrementCallCount,
                     Arbitrary<std::tuple<int>>(), {});

  CallCountFixture::call_count = 0;

  fixture_driver.SetUpFuzzTest();
  fixture_driver.SetUpIteration();
  fixture_driver.Test(MakeArgs(7));

  EXPECT_EQ(CallCountFixture::call_count, 7);
}

TEST(FixtureDriverTest, ReusesSameFixtureObjectDuringFuzzTest) {
  FixtureDriverImpl<Domain<std::tuple<int>>, CallCountFixture,
                    IncrementCallCountFunc>
      fixture_driver(&CallCountFixture::IncrementCallCount,
                     Arbitrary<std::tuple<int>>(), {});

  CallCountFixture::call_count = 0;

  fixture_driver.SetUpFuzzTest();
  fixture_driver.SetUpIteration();
  fixture_driver.Test(MakeArgs(3));
  fixture_driver.TearDownIteration();
  fixture_driver.SetUpIteration();
  fixture_driver.Test(MakeArgs(3));
  fixture_driver.TearDownIteration();
  fixture_driver.SetUpIteration();
  fixture_driver.Test(MakeArgs(4));

  EXPECT_EQ(CallCountFixture::call_count, 10);
}

struct DerivedCallCountFixture : CallCountFixture {};

TEST(FixtureDriverTest, PropagatesCallToTargetFunctionOnBaseFixture) {
  FixtureDriverImpl<Domain<std::tuple<int>>, DerivedCallCountFixture,
                    IncrementCallCountFunc>
      fixture_driver(&DerivedCallCountFixture::IncrementCallCount,
                     Arbitrary<std::tuple<int>>(), {});

  CallCountFixture::call_count = 0;

  fixture_driver.SetUpFuzzTest();
  fixture_driver.SetUpIteration();
  fixture_driver.Test(MakeArgs(3));

  EXPECT_EQ(CallCountFixture::call_count, 3);
}

struct LifecycleRecordingFixture {
  LifecycleRecordingFixture() { was_constructed = true; }
  ~LifecycleRecordingFixture() { was_destructed = true; }

  void NoOp() {}

  static void Reset() {
    was_constructed = false;
    was_destructed = false;
  }

  static bool was_constructed;
  static bool was_destructed;
};

bool LifecycleRecordingFixture::was_constructed = false;
bool LifecycleRecordingFixture::was_destructed = false;

TEST(FixtureDriverTest, FixtureGoesThroughCompleteLifecycle) {
  using NoOpFunc = decltype(&LifecycleRecordingFixture::NoOp);
  FixtureDriverImpl<Domain<std::tuple<>>, LifecycleRecordingFixture, NoOpFunc>
      fixture_driver(&LifecycleRecordingFixture::NoOp,
                     Arbitrary<std::tuple<>>(), {});

  LifecycleRecordingFixture::Reset();

  ASSERT_TRUE(!LifecycleRecordingFixture::was_constructed &&
              !LifecycleRecordingFixture::was_destructed);

  fixture_driver.SetUpFuzzTest();
  fixture_driver.SetUpIteration();

  EXPECT_TRUE(LifecycleRecordingFixture::was_constructed);

  fixture_driver.TearDownIteration();

  EXPECT_TRUE(!LifecycleRecordingFixture::was_destructed);

  fixture_driver.TearDownFuzzTest();

  EXPECT_TRUE(LifecycleRecordingFixture::was_destructed);
}

template <typename InstantiationType>
struct LifecycleRecordingFixtureWithExplicitSetUp : LifecycleRecordingFixture,
                                                    InstantiationType {
  ~LifecycleRecordingFixtureWithExplicitSetUp() override {
    LifecycleRecordingFixture::~LifecycleRecordingFixture();
  }

  void SetUp() override { was_set_up = true; }
  void TearDown() override { was_torn_down = true; }

  static void Reset() {
    LifecycleRecordingFixture::Reset();
    was_set_up = false;
    was_torn_down = false;
  }

  static bool was_set_up;
  static bool was_torn_down;
};

template <typename InstantiationType>
bool LifecycleRecordingFixtureWithExplicitSetUp<InstantiationType>::was_set_up =
    false;
template <typename InstantiationType>
bool LifecycleRecordingFixtureWithExplicitSetUp<
    InstantiationType>::was_torn_down = false;

TEST(FixtureDriverTest, PerIterationFixtureGoesThroughCompleteLifecycle) {
  using LifecycleRecordingPerIterationFixture =
      LifecycleRecordingFixtureWithExplicitSetUp<PerIterationFixture>;
  using NoOpFunc = decltype(&LifecycleRecordingPerIterationFixture::NoOp);
  FixtureDriverImpl<Domain<std::tuple<>>, LifecycleRecordingPerIterationFixture,
                    NoOpFunc>
      fixture_driver(&LifecycleRecordingPerIterationFixture::NoOp,
                     Arbitrary<std::tuple<>>(), {});

  LifecycleRecordingPerIterationFixture::Reset();

  ASSERT_TRUE(!LifecycleRecordingPerIterationFixture::was_constructed &&
              !LifecycleRecordingPerIterationFixture::was_set_up &&
              !LifecycleRecordingPerIterationFixture::was_torn_down &&
              !LifecycleRecordingPerIterationFixture::was_destructed);

  fixture_driver.SetUpFuzzTest();
  fixture_driver.SetUpIteration();

  EXPECT_TRUE(LifecycleRecordingPerIterationFixture::was_constructed &&
              LifecycleRecordingPerIterationFixture::was_set_up &&
              !LifecycleRecordingPerIterationFixture::was_torn_down &&
              !LifecycleRecordingPerIterationFixture::was_destructed);

  fixture_driver.TearDownIteration();

  EXPECT_TRUE(LifecycleRecordingPerIterationFixture::was_torn_down &&
              LifecycleRecordingPerIterationFixture::was_destructed);
}

TEST(FixtureDriverTest, PerFuzzTestFixtureGoesThroughCompleteLifecycle) {
  using LifecycleRecordingPerFuzzTestFixture =
      LifecycleRecordingFixtureWithExplicitSetUp<PerFuzzTestFixture>;
  using NoOpFunc = decltype(&LifecycleRecordingPerFuzzTestFixture::NoOp);
  FixtureDriverImpl<Domain<std::tuple<>>, LifecycleRecordingPerFuzzTestFixture,
                    NoOpFunc>
      fixture_driver(&LifecycleRecordingPerFuzzTestFixture::NoOp,
                     Arbitrary<std::tuple<>>(), {});
  LifecycleRecordingPerFuzzTestFixture::Reset();

  ASSERT_TRUE(!LifecycleRecordingPerFuzzTestFixture::was_constructed &&
              !LifecycleRecordingPerFuzzTestFixture::was_set_up &&
              !LifecycleRecordingPerFuzzTestFixture::was_torn_down &&
              !LifecycleRecordingPerFuzzTestFixture::was_destructed);

  fixture_driver.SetUpFuzzTest();
  fixture_driver.SetUpIteration();

  EXPECT_TRUE(LifecycleRecordingPerFuzzTestFixture::was_constructed &&
              LifecycleRecordingPerFuzzTestFixture::was_set_up);

  fixture_driver.TearDownIteration();

  EXPECT_TRUE(!LifecycleRecordingPerFuzzTestFixture::was_torn_down &&
              !LifecycleRecordingPerFuzzTestFixture::was_destructed);

  fixture_driver.TearDownFuzzTest();

  EXPECT_TRUE(LifecycleRecordingPerFuzzTestFixture::was_torn_down &&
              LifecycleRecordingPerFuzzTestFixture::was_destructed);
}

}  // namespace
}  // namespace fuzztest::internal
