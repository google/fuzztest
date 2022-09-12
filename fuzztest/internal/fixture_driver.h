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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_FIXTURE_DRIVER_H_
#define FUZZTEST_FUZZTEST_INTERNAL_FIXTURE_DRIVER_H_

#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/registration.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

// The interface for test fixtures with setup and teardown methods that need to
// be explicitly called by the testing framework.
class FixtureWithExplicitSetUp {
 public:
  virtual ~FixtureWithExplicitSetUp() = default;

  virtual void SetUp() = 0;
  virtual void TearDown() = 0;

  static void SetUpTestSuite() {}
  static void TearDownTestSuite() {}
};

// Marker interfaces for specifying the fixture's instantiation semantics:
//
// -  Per-iteration semantics: The fixture object is instantiated and discarded
//    once per fuzz test iteration.
//
// -  Per-fuzz-test semantics: The fixture object is instantiated and discarded
//    once per fuzz test. The same  object is reused in all fuzz test
//    iterations.
class PerIterationFixture : public FixtureWithExplicitSetUp {};
class PerFuzzTestFixture : public FixtureWithExplicitSetUp {};

// The base class for fixture drivers.
//
// A fixture driver is used for maintaining a fixture -- constructing it,
// setting it up, tearing it down, and destructing it -- during a fuzz test. It
// also acts as a proxy to the fixture's target function.
//
// The type parameters are:
//   - `RegBase` -- the base class for `Registration` that determines whether
//                  the fuzz test was registered with domains and seeds.
//   - `Fixture` -- the type of the test fixture.
//   - `TargetFunction` -- the type of the fixture's target function.
//   - Unnamed type used in SFINAE resolution.
template <typename RegBase, typename Fixture, typename TargetFunction,
          typename = void>
class FixtureDriver;

// The specialization of the fixture driver base class template.
//
// The type parameters are:
//   - `RegBase` -- the base class for `Registration` that determines whether
//                  the fuzz test was registered with domains and seeds.
//   - `Fixture` -- the type of the test fixture.
//   - `BaseFixture` -- the class from which `Fixture` is derived and which has
//                      the target function.
//   - `Args...` -- the types of the target function's parameters.
template <typename RegBase, typename Fixture, typename BaseFixture,
          typename... Args>
class FixtureDriver<RegBase, Fixture, void (BaseFixture::*)(Args...),
                    std::enable_if_t<std::is_base_of_v<BaseFixture, Fixture>>> {
 public:
  using TargetFunction = void (BaseFixture::*)(Args...);

  explicit FixtureDriver(
      Registration<Fixture, TargetFunction, RegBase> registration)
      : registration_(std::move(registration)) {}

  // The destructor is pure virtual to make the class abstract.
  virtual ~FixtureDriver() = 0;

  FixtureDriver(FixtureDriver&&) noexcept;
  FixtureDriver& operator=(FixtureDriver&&) = default;

  // Methods for setting up and tearing down the fixture. All fixture driver
  // implementations must ensure that every sequence of calls of the form
  //
  //  SetUpFuzzTest() SetUpIteration() [ TearDownIteration() SetUpIteration() ]*
  //
  // results in `fixture_ != nullptr`. Likewise, continuing any such sequence
  // with calls to
  //
  //  TearDownIteration() TearDownFuzzTest()
  //
  // must result in `fixture_ == nullptr`.
  virtual void SetUpFuzzTest() {}
  virtual void SetUpIteration() {}
  virtual void TearDownIteration() {}
  virtual void TearDownFuzzTest() {}

  void Test(Args... args) {
    FUZZTEST_INTERNAL_CHECK_PRECONDITION(
        fixture_ != nullptr,
        "fixture is nullptr. Did you forget to instantiate it in one of the "
        "SetUp methods?");
    (fixture_.get()->*registration_.target_function_)(std::move(args)...);
  }

  decltype(auto) GetSeeds() const {
    if constexpr (Registration<Fixture, TargetFunction, RegBase>::kHasSeeds) {
      return registration_.seeds_;
    } else {
      return std::vector<corpus_type_t<decltype(GetDomains())>>{};
    }
  }

  auto GetDomains() const { return registration_.GetDomains(); }

 protected:
  // The fixture managed by the fixture driver.
  std::unique_ptr<Fixture> fixture_;

 private:
  // The registration that was used to register the fuzz test. Stores
  // the pointer to the target function, and the domains and the seeds for the
  // target function's parameters.
  Registration<Fixture, TargetFunction, RegBase> registration_;
};

template <typename RegBase, typename Fixture, typename BaseFixture,
          typename... Args>
FixtureDriver<RegBase, Fixture, void (BaseFixture::*)(Args...),
              std::enable_if_t<std::is_base_of_v<BaseFixture, Fixture>>>::
    ~FixtureDriver() = default;

template <typename RegBase, typename Fixture, typename BaseFixture,
          typename... Args>
FixtureDriver<RegBase, Fixture, void (BaseFixture::*)(Args...),
              std::enable_if_t<std::is_base_of_v<BaseFixture, Fixture>>>::
    FixtureDriver(FixtureDriver&&) noexcept = default;

template <typename RegBase, typename Fixture, typename TargetFunction,
          typename = void>
class FixtureDriverImpl;

// The fixture driver for default-constructible classes that act like fixtures:
// their setup is in the constructor, teardown is in the destructor, and they
// have a target function. Such fixtures are instantiated and destructed once
// per fuzz test.
template <typename RegBase, typename Fixture, typename BaseFixture,
          typename... Args>
class FixtureDriverImpl<
    RegBase, Fixture, void (BaseFixture::*)(Args...),
    std::enable_if_t<std::conjunction_v<
        std::is_default_constructible<Fixture>,
        std::is_base_of<BaseFixture, Fixture>,
        std::negation<std::is_base_of<FixtureWithExplicitSetUp, Fixture>>>>>
    final
    : public FixtureDriver<RegBase, Fixture, void (BaseFixture::*)(Args...)> {
 public:
  using FixtureDriver<RegBase, Fixture,
                      void (BaseFixture::*)(Args...)>::FixtureDriver;

  void SetUpFuzzTest() override {
    this->fixture_ = std::make_unique<Fixture>();
  }
  void TearDownFuzzTest() override { this->fixture_ = nullptr; }
};

// The fixture driver for test fixtures with explicit setup that assume the
// "per-iteration" semantics.
template <typename RegBase, typename Fixture, typename BaseFixture,
          typename... Args>
class FixtureDriverImpl<RegBase, Fixture, void (BaseFixture::*)(Args...),
                        std::enable_if_t<std::conjunction_v<
                            std::is_default_constructible<Fixture>,
                            std::is_base_of<BaseFixture, Fixture>,
                            std::is_base_of<PerIterationFixture, Fixture>>>>
    final
    : public FixtureDriver<RegBase, Fixture, void (BaseFixture::*)(Args...)> {
 public:
  using FixtureDriver<RegBase, Fixture,
                      void (BaseFixture::*)(Args...)>::FixtureDriver;

  void SetUpIteration() override {
    this->fixture_ = std::make_unique<Fixture>();
    this->fixture_->SetUp();
  }
  void TearDownIteration() override {
    this->fixture_->TearDown();
    this->fixture_ = nullptr;
  }
};

// The fixture driver for test fixtures with explicit setup that assume the
// "per-fuzz-test" semantics.
template <typename RegBase, typename Fixture, typename BaseFixture,
          typename... Args>
class FixtureDriverImpl<RegBase, Fixture, void (BaseFixture::*)(Args...),
                        std::enable_if_t<std::conjunction_v<
                            std::is_default_constructible<Fixture>,
                            std::is_base_of<BaseFixture, Fixture>,
                            std::is_base_of<PerFuzzTestFixture, Fixture>>>>
    final
    : public FixtureDriver<RegBase, Fixture, void (BaseFixture::*)(Args...)> {
 public:
  using FixtureDriver<RegBase, Fixture,
                      void (BaseFixture::*)(Args...)>::FixtureDriver;

  void SetUpFuzzTest() override {
    this->fixture_ = std::make_unique<Fixture>();
    this->fixture_->SetUp();
  }
  void TearDownFuzzTest() override {
    this->fixture_->TearDown();
    this->fixture_ = nullptr;
  }
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_FIXTURE_DRIVER_H_
