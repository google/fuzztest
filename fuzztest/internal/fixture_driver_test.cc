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
#include "./fuzztest/internal/domain.h"
#include "./fuzztest/internal/registration.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {
namespace {

using ::testing::IsEmpty;
using ::testing::UnorderedElementsAre;

struct CallCountFixture {
  void IncrementCallCount(int* current_call_count) {
    ++call_count;
    if (current_call_count != nullptr) {
      *current_call_count = call_count;
    }
  }
  int call_count = 0;
};

using IncrementCallCountFunc = decltype(&CallCountFixture::IncrementCallCount);
using CallCountRegBase =
    DefaultRegistrationBase<CallCountFixture, IncrementCallCountFunc>;

TEST(FixtureDriverTest, PropagatesCallToTargetFunction) {
  FixtureDriverImpl<CallCountRegBase, CallCountFixture, IncrementCallCountFunc>
      fixture_driver(Registration<CallCountFixture, IncrementCallCountFunc>(
          {"SuiteName", "TestName", "/test/file", /*line=*/1},
          &CallCountFixture::IncrementCallCount));
  int target_function_call_count = 0;

  fixture_driver.SetUpFuzzTest();
  fixture_driver.SetUpIteration();
  fixture_driver.Test(&target_function_call_count);

  EXPECT_EQ(target_function_call_count, 1);
}

TEST(FixtureDriverTest, ReusesSameFixtureObjectDuringFuzzTest) {
  FixtureDriverImpl<CallCountRegBase, CallCountFixture, IncrementCallCountFunc>
      fixture_driver(Registration<CallCountFixture, IncrementCallCountFunc>(
          {"SuiteName", "TestName", "/test/file", /*line=*/1},
          &CallCountFixture::IncrementCallCount));
  int target_function_call_count = 0;

  fixture_driver.SetUpFuzzTest();
  fixture_driver.SetUpIteration();
  fixture_driver.Test(&target_function_call_count);
  fixture_driver.TearDownIteration();
  fixture_driver.SetUpIteration();
  fixture_driver.Test(&target_function_call_count);
  fixture_driver.TearDownIteration();
  fixture_driver.SetUpIteration();
  fixture_driver.Test(&target_function_call_count);

  EXPECT_EQ(target_function_call_count, 3);
}

struct DerivedCallCountFixture : CallCountFixture {};

TEST(FixtureDriverTest, PropagatesCallToTargetFunctionOnBaseFixture) {
  using RegBase =
      DefaultRegistrationBase<DerivedCallCountFixture, IncrementCallCountFunc>;
  FixtureDriverImpl<RegBase, DerivedCallCountFixture, IncrementCallCountFunc>
      fixture_driver(
          Registration<DerivedCallCountFixture, IncrementCallCountFunc>(
              {"SuiteName", "TestName", "/test/file", /*line=*/1},
              &DerivedCallCountFixture::IncrementCallCount));
  int target_function_call_count = 0;

  fixture_driver.SetUpFuzzTest();
  fixture_driver.SetUpIteration();
  fixture_driver.Test(&target_function_call_count);

  EXPECT_EQ(target_function_call_count, 1);
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
  using RegBase = DefaultRegistrationBase<LifecycleRecordingFixture, NoOpFunc>;
  FixtureDriverImpl<RegBase, LifecycleRecordingFixture, NoOpFunc>
      fixture_driver(Registration<LifecycleRecordingFixture, NoOpFunc>(
          {"SuiteName", "TestName", "/test/file", /*line=*/1},
          &LifecycleRecordingFixture::NoOp));
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
  using RegBase =
      DefaultRegistrationBase<LifecycleRecordingPerIterationFixture, NoOpFunc>;
  FixtureDriverImpl<RegBase, LifecycleRecordingPerIterationFixture, NoOpFunc>
      fixture_driver(
          Registration<LifecycleRecordingPerIterationFixture, NoOpFunc>(
              {"SuiteName", "TestName", "/test/file", /*line=*/1},
              &LifecycleRecordingPerIterationFixture::NoOp));
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
  using RegBase =
      DefaultRegistrationBase<LifecycleRecordingPerFuzzTestFixture, NoOpFunc>;
  FixtureDriverImpl<RegBase, LifecycleRecordingPerFuzzTestFixture, NoOpFunc>
      fixture_driver(
          Registration<LifecycleRecordingPerFuzzTestFixture, NoOpFunc>(
              {"SuiteName", "TestName", "/test/file", /*line=*/1},
              &LifecycleRecordingPerFuzzTestFixture::NoOp));
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

struct IntFixture {
  void Foo(int) {}
};

using FooFunc = decltype(&IntFixture::Foo);

TEST(FixtureDriverTest, GetsEmptySeedsFromUnseededRegistration) {
  using UnseededRegBase = DefaultRegistrationBase<IntFixture, FooFunc>;
  FixtureDriverImpl<UnseededRegBase, IntFixture, FooFunc> fixture_driver(
      Registration<IntFixture, FooFunc>(
          {"SuiteName", "TestName", "/test/file", /*line=*/1},
          &IntFixture::Foo));

  EXPECT_THAT(fixture_driver.GetSeeds(), IsEmpty());
}

TEST(FixtureDriverTest, PropagatesSeedsFromSeededRegistration) {
  using SeededRegBase =
      RegistrationWithSeedsBase<DefaultRegistrationBase<IntFixture, FooFunc>>;
  FixtureDriverImpl<SeededRegBase, IntFixture, FooFunc> fixture_driver(
      Registration<IntFixture, FooFunc>(
          {"SuiteName", "TestName", "/test/file", /*line=*/1}, &IntFixture::Foo)
          .WithSeeds({111, 222})
          .WithSeeds({333}));

  EXPECT_THAT(
      fixture_driver.GetSeeds(),
      UnorderedElementsAre(std::tuple{111}, std::tuple{222}, std::tuple{333}));
}

TEST(FixtureDriverTest, PropagatesDomainsFromRegistrationWithDomains) {
  using PositiveInt = decltype(TupleOf(Positive<int>()));
  using RegBaseWithDomains = RegistrationWithDomainsBase<PositiveInt>;
  FixtureDriverImpl<RegBaseWithDomains, IntFixture, FooFunc> fixture_driver(
      Registration<IntFixture, FooFunc>(
          {"SuiteName", "TestName", "/test/file", /*line=*/1}, &IntFixture::Foo)
          .WithDomains(Positive<int>()));

  static_assert(
      std::is_same_v<std::decay_t<decltype(fixture_driver.GetDomains())>,
                     PositiveInt>);
}

}  // namespace
}  // namespace fuzztest::internal
