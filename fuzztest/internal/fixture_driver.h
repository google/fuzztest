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
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "./fuzztest/internal/domains/domain_base.h"
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

class UntypedFixtureDriver {
 public:
  UntypedFixtureDriver(std::unique_ptr<UntypedDomainInterface> domain,
                       std::vector<GenericDomainCorpusType> seeds);
  virtual ~UntypedFixtureDriver() = 0;

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
  virtual void SetUpFuzzTest();
  virtual void SetUpIteration();
  virtual void TearDownIteration();
  virtual void TearDownFuzzTest();

  // We take by rvalue ref to allow moving from it if necessary, but we want to
  // delay destroying the value until after instrumentation is turned off in the
  // caller.
  virtual void Test(MoveOnlyAny&& args_untyped) const = 0;

  std::vector<GenericDomainCorpusType> GetSeeds() const;
  virtual std::vector<GenericDomainCorpusType> GetDynamicSeeds();
  std::unique_ptr<UntypedDomainInterface> GetDomains() const;

 private:
  std::unique_ptr<UntypedDomainInterface> domain_;
  std::vector<GenericDomainCorpusType> seeds_;
};

// ForceVectorForStringView is a temporary hack for realiably
// finding buffer overflows. ASAN cannot detect small overflows in
// std::string-s. See related bug at
// https://bugs.llvm.org/show_bug.cgi?id=26380. As a temporary
// workaround, we enable finding overflows by copying the contents
// of the original string into a separate temporary heap buffer.
// TODO(b/194687521): Remove this when we (or ASAN) detect overflows
// in strings.
struct ForceVector {
  operator std::string_view() const { return {value.data(), value.size()}; }
  std::vector<char> value;
};

template <typename Dest, typename Src>
decltype(auto) ForceVectorForStringView(Src&& src) {
  // We only do this when Src is a std::string. If it's a string view it is
  // handled by the string view domain itself.
  if constexpr (std::is_same_v<void(std::decay_t<Dest>, std::decay_t<Src>),
                               void(std::string_view, std::string)>) {
    return ForceVector{std::vector<char>(src.begin(), src.end())};
  } else {
    return std::forward<Src>(src);
  }
}

// The base class for fixture drivers.
//
// A fixture driver is used for maintaining a fixture -- constructing it,
// setting it up, tearing it down, and destructing it -- during a fuzz test. It
// also acts as a proxy to the fixture's target function.
//
// The type parameters are:
//   - `DomainT` -- the type of the domain. Eg `Domain<std::tuple<int>>`.
//   - `Fixture` -- the type of the test fixture.
//   - `TargetFunction` -- the type of the fixture's target function.
template <typename DomainT, typename Fixture, typename TargetFunction>
class FixtureDriver;

// Specialization for `TargetFunction = void(BaseFixture::*)(Args...)`
//
// The new type parameters are:
//   - `BaseFixture` -- the class from which `Fixture` is derived and which has
//                      the target function.
//   - `Args...` -- the types of the target function's parameters.
template <typename DomainT, typename Fixture, typename BaseFixture,
          typename... Args>
class FixtureDriver<DomainT, Fixture, void (BaseFixture::*)(Args...)>
    : public UntypedFixtureDriver {
 public:
  static_assert(std::is_base_of_v<BaseFixture, Fixture>);
  using TargetFunction = void (BaseFixture::*)(Args...);

  explicit FixtureDriver(TargetFunction target_function, const DomainT& domain,
                         std::vector<GenericDomainCorpusType> seeds)
      : UntypedFixtureDriver(domain.Clone(), std::move(seeds)),
        target_function_(target_function) {}

  void Test(MoveOnlyAny&& args_untyped) const override {
    FUZZTEST_INTERNAL_CHECK_PRECONDITION(
        fixture_ != nullptr,
        "fixture is nullptr. Did you forget to instantiate it in one of the "
        "SetUp methods?");
    std::apply(
        [&](auto&&... args) {
          (fixture_.get()->*target_function_)(
              ForceVectorForStringView<Args>(std::move(args))...);
        },
        args_untyped.GetAs<value_type_t<DomainT>>());
  }

 protected:
  // The fixture managed by the fixture driver.
  std::unique_ptr<Fixture> fixture_;

 private:
  TargetFunction target_function_;
};

// Specialization for `Fixture = NoFixture`.
// This is used for FUZZ_TEST invocations that do not require a fixture.
// TargetFunction must be `void(*)(Args...)`
//
// The new type parameters are:
//   - `Args...` -- the types of the target function's parameters.
template <typename DomainT, typename... Args>
class FixtureDriver<DomainT, NoFixture, void (*)(Args...)>
    : public UntypedFixtureDriver {
 public:
  using TargetFunction = void (*)(Args...);

  explicit FixtureDriver(TargetFunction target_function, const DomainT& domain,
                         std::vector<GenericDomainCorpusType> seeds)
      : UntypedFixtureDriver(domain.Clone(), std::move(seeds)),
        target_function_(target_function) {}

  void Test(MoveOnlyAny&& args_untyped) const override {
    std::apply(
        [&](auto&&... args) {
          target_function_(ForceVectorForStringView<Args>(std::move(args))...);
        },
        args_untyped.GetAs<value_type_t<DomainT>>());
  }

 private:
  TargetFunction target_function_;
};

template <typename DomainT, typename Fixture, typename TargetFunction,
          typename = void>
class FixtureDriverImpl;

// The fixture driver for "NoFixture", which is the tag used for the FUZZ_TEST
// macro that uses no fixtures. No fixture is created.
template <typename DomainT, typename TargetFunction>
class FixtureDriverImpl<DomainT, NoFixture, TargetFunction> final
    : public FixtureDriver<DomainT, NoFixture, TargetFunction> {
 public:
  using FixtureDriver<DomainT, NoFixture, TargetFunction>::FixtureDriver;
};

// HasGetDynamicSeeds<T>::value is true_type if T has a
// GetDynamicSeeds() member.
template <typename T, typename = void>
struct HasGetDynamicFuzzTestSeeds : std::false_type {};

template <typename T>
struct HasGetDynamicFuzzTestSeeds<
    T, std::void_t<decltype(std::declval<T>().GetDynamicFuzzTestSeeds())>>
    : std::true_type {};

// The fixture driver for default-constructible classes that act like fixtures:
// their setup is in the constructor, teardown is in the destructor, and they
// have a target function. Such fixtures are instantiated and destructed once
// per fuzz test.
template <typename DomainT, typename Fixture, typename TargetFunction>
class FixtureDriverImpl<
    DomainT, Fixture, TargetFunction,
    std::enable_if_t<std::conjunction_v<
        std::is_default_constructible<Fixture>,
        std::negation<std::is_base_of<FixtureWithExplicitSetUp, Fixture>>>>>
    final : public FixtureDriver<DomainT, Fixture, TargetFunction> {
 public:
  using FixtureDriver<DomainT, Fixture, TargetFunction>::FixtureDriver;

  void SetUpFuzzTest() override {
    this->fixture_ = std::make_unique<Fixture>();
  }
  void TearDownFuzzTest() override { this->fixture_ = nullptr; }

  std::vector<GenericDomainCorpusType> GetDynamicSeeds() override {
    std::vector<GenericDomainCorpusType> seeds;
    if constexpr (HasGetDynamicFuzzTestSeeds<Fixture>::value) {
      auto typed_seeds = this->fixture_->GetDynamicFuzzTestSeeds();
      seeds.reserve(typed_seeds.size());
      for (auto& seed : typed_seeds) {
        seeds.emplace_back(std::in_place_type<std::decay_t<decltype(seed)>>,
                           std::move(seed));
      }
    }
    return seeds;
  }
};

// The fixture driver for test fixtures with explicit setup that assume the
// "per-iteration" semantics.
template <typename DomainT, typename Fixture, typename BaseFixture,
          typename... Args>
class FixtureDriverImpl<DomainT, Fixture, void (BaseFixture::*)(Args...),
                        std::enable_if_t<std::conjunction_v<
                            std::is_default_constructible<Fixture>,
                            std::is_base_of<BaseFixture, Fixture>,
                            std::is_base_of<PerIterationFixture, Fixture>>>>
    final
    : public FixtureDriver<DomainT, Fixture, void (BaseFixture::*)(Args...)> {
 public:
  using FixtureDriver<DomainT, Fixture,
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
template <typename DomainT, typename Fixture, typename BaseFixture,
          typename... Args>
class FixtureDriverImpl<DomainT, Fixture, void (BaseFixture::*)(Args...),
                        std::enable_if_t<std::conjunction_v<
                            std::is_default_constructible<Fixture>,
                            std::is_base_of<BaseFixture, Fixture>,
                            std::is_base_of<PerFuzzTestFixture, Fixture>>>>
    final
    : public FixtureDriver<DomainT, Fixture, void (BaseFixture::*)(Args...)> {
 public:
  using FixtureDriver<DomainT, Fixture,
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
