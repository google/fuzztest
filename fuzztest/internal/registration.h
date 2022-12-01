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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_REGISTRATION_H_
#define FUZZTEST_FUZZTEST_INTERNAL_REGISTRATION_H_

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "absl/strings/str_format.h"
#include "absl/types/span.h"
#include "./fuzztest/domain.h"
#include "./fuzztest/internal/domain.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

struct BasicTestInfo {
  const char* suite_name = nullptr;
  const char* test_name = nullptr;
  const char* file = nullptr;
  int line = 0;
  bool uses_fixture = false;
};

// Use base classes to progressively add members/behavior to the registerer
// object. This way we can statically assert that certain functions are called
// in the right order.

template <typename Fixture, typename TargetFunction, typename = void>
struct DefaultRegistrationBase;

// Initial base class. No custom domain, no seeds.
template <typename Fixture, typename BaseFixture, typename... Args>
struct DefaultRegistrationBase<
    Fixture, void (BaseFixture::*)(Args...),
    std::enable_if_t<std::is_base_of_v<BaseFixture, Fixture>>> {
  static constexpr bool kHasDomain = false;
  static constexpr bool kHasSeeds = false;

  auto GetDomains() const {
    return TupleOf(Arbitrary<std::decay_t<Args>>()...);
  }

  using SeedT = std::tuple<std::decay_t<Args>...>;
};

// A custom domain was specified.
template <typename Domain>
struct RegistrationWithDomainsBase {
  static constexpr bool kHasDomain = true;
  static constexpr bool kHasSeeds = false;

  Domain domains_;

  const auto& GetDomains() const { return domains_; }

  using SeedT = decltype(domains_.GetValue({}));
};

// Seeds were specified. It derived from the existing base to augment it.
template <typename Base>
struct RegistrationWithSeedsBase : Base {
  static constexpr bool kHasSeeds = true;

  explicit RegistrationWithSeedsBase(Base base) : Base(std::move(base)) {}

  std::vector<
      corpus_type_t<std::decay_t<decltype(std::declval<Base>().GetDomains())>>>
      seeds_;
};

template <typename Fixture, typename TargetFunction,
          typename Base = DefaultRegistrationBase<Fixture, TargetFunction>,
          typename = void>
class Registration;

struct RegistrationToken;

template <typename RegBase, typename Fixture, typename TargetFunction, typename>
class FixtureDriver;

template <typename Fixture, typename BaseFixture, typename... Args,
          typename Base>
class Registration<Fixture, void (BaseFixture::*)(Args...), Base,
                   std::enable_if_t<std::is_base_of_v<BaseFixture, Fixture>>>
    : private Base {
  using TargetFunction = void (BaseFixture::*)(Args...);
  using SeedT = typename Base::SeedT;

 public:
  explicit Registration(BasicTestInfo info, TargetFunction target_function)
      : test_info_(info), target_function_(target_function) {}

  // Registers domains for a property function as a `TupleOf` individual
  // domains. This is useful when the domains are specified indirectly, e.g.,
  // when they are returned from a helper function. For example:
  //
  // auto StringAndIndex(int size) {
  //   return TupleOf(String().WithSize(size), InRange(0, size - 1));
  // }
  //
  // void MyProperty(std::string s, int i) { ... }
  // FUZZ_TEST(MySuite, MyProperty).WithDomains(StringAndIndex(10));
  template <typename... NewDomains>
  auto WithDomains(
      AggregateOfImpl<std::tuple<typename NewDomains::value_type...>,
                      RequireCustomCorpusType::kNo, NewDomains...>
          domain) && {
    static_assert(!Registration::kHasDomain,
                  "WithDomains can only be called once.");
    static_assert(!Registration::kHasSeeds,
                  "WithDomains can not be called after WithSeeds.");
    static_assert(
        sizeof...(Args) == sizeof...(NewDomains),
        "Number of domains specified in .WithDomains() does not match "
        "the number of function parameters.");
    return Registration<Fixture, TargetFunction,
                        RegistrationWithDomainsBase<decltype(domain)>>(
        test_info_, target_function_,
        RegistrationWithDomainsBase<decltype(domain)>{std::move(domain)});
  }

  // Registers a domain for each parameter of the property function. This is the
  // recommended approach when domains are explicitly listed as part of the fuzz
  // test definition. For example:
  //
  // void MyProperty(std::string s, int n) { ... }
  // FUZZ_TEST(MySuite, MyProperty).WithDomains(String(), Positive<int>());
  template <typename... NewDomains>
  auto WithDomains(NewDomains&&... domains) && {
    return std::move(*this).WithDomains(
        TupleOf(std::forward<NewDomains>(domains)...));
  }

  // fuzztest currently _doesn't_ support this pattern:
  //
  // void MyProperty(std::string s, int i) { ... }
  // FUZZ_TEST(MySuite, MyProperty).WithDomains(
  //   FlatMap([](...) { return TupleOf(<string domain>, <int domain>); }));
  //
  // This overload catches this case and provides a more helpful error than we
  // otherwise give, which is to complain that the number of args and domains
  // don't match (e.g. for the example above):
  //
  // static assertion failed due to requirement 'sizeof...(Args) ==
  // sizeof...(NewDomains)'
  // [...]
  // Expression evaluates to '2 == 1'
  template <
      typename... FlatMapArgs, typename FlatMap = FlatMapImpl<FlatMapArgs...>,
      // Enable this overload when we receive a single top-level FlatMap that
      // returns TupleOf, and the property function doesn't have a matching
      // signature.
      typename = std::enable_if_t<
          is_aggregate_of_v<typename FlatMap::output_domain> &&
          !std::conjunction_v<
              std::is_convertible<typename FlatMap::value_type, Args>...>>>
  auto WithDomains(FlatMapImpl<FlatMapArgs...>&& domain) && {
    static_assert(
        std::conjunction_v<
            std::is_convertible<typename FlatMap::value_type, Args>...>,
        "Property function must accept std::tuple<...> when specifying "
        ".WithDomains(FlatMap()) returning TupleOf.");
    return std::move(*this);
  }

  auto WithSeeds(absl::Span<const SeedT> seeds) && {
    if constexpr (!Registration::kHasSeeds) {
      return Registration<Fixture, TargetFunction,
                          RegistrationWithSeedsBase<Base>>(
                 test_info_, target_function_,
                 RegistrationWithSeedsBase<Base>(std::move(*this)))
          .WithSeeds(seeds);
    } else {
      const auto& domains = this->GetDomains();
      bool found_error = false;
      for (const auto& seed : seeds) {
        if (auto from_value = domains.FromValue(seed)) {
          this->seeds_.push_back(*std::move(from_value));
        } else {
          // TODO(sbenzaquen): Should we abort the process or make the test fail
          // when seeds are ignored?
          absl::FPrintF(
              stderr,
              "[!] Error using `WithSeeds()` in %s.%s:\n\n%s:%d: Invalid seed "
              "value:\n\n{",
              test_info_.suite_name, test_info_.test_name, test_info_.file,
              test_info_.line);

          // We use a direct call to PrintUserValue because we don't have a
          // corpus_type object to pass to PrintValue.
          bool first = true;
          const auto print_one_arg = [&](auto I) {
            using value_type = std::decay_t<std::tuple_element_t<I, SeedT>>;
            AutodetectTypePrinter<value_type>().PrintUserValue(
                std::get<I>(seed), &std::cerr, PrintMode::kHumanReadable);
            if (!first) absl::FPrintF(stderr, ", ");
            first = false;
          };
          ApplyIndex<sizeof...(Args)>(
              [&](auto... I) { (print_one_arg(I), ...); });

          absl::FPrintF(stderr, "}\n");
          found_error = true;
        }
      }
      if (found_error) exit(1);
      return std::move(*this);
    }
  }

 private:
  template <typename, typename, typename, typename>
  friend class Registration;
  friend struct RegistrationToken;
  friend class FixtureDriver<
      Base, Fixture, TargetFunction,
      std::enable_if_t<std::is_base_of_v<BaseFixture, Fixture>>>;

  explicit Registration(BasicTestInfo info, TargetFunction target_function,
                        Base base)
      : Base(std::move(base)),
        test_info_(info),
        target_function_(target_function) {}

  BasicTestInfo test_info_;
  TargetFunction target_function_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_REGISTRATION_H_
