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

#ifndef FUZZTEST_FUZZTEST_FUZZTEST_H_
#define FUZZTEST_FUZZTEST_FUZZTEST_H_

#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "./fuzztest/domain.h"
#include "./fuzztest/internal/registry.h"

namespace fuzztest {

// The FUZZ_TEST macro registers a fuzz test.
//
// Fuzz tests are parameterized unit tests, also called property-based tests.
// The tested property is captured by a function with some parameters, and the
// input domains of the parameters can be specified with the FUZZ_TEST macro
// that registers and instantiates the test:
//
//   void CallingMyApiNeverCrashes(int x, const std::string& s) {
//     bool result = MyApi(x, s);  // This function call should never crash.
//     ASSERT_TRUE(result);        // Can have explicit assertions too.
//   }
//   FUZZ_TEST(MySuite, CallingMyApiNeverCrashes)
//     .WithDomains(/*x:*/fuzztest::InRange(0,10),
//                  /*s:*/fuzztest::AsciiString())
//     .WithSeeds({{5, "Foo"}, {10, "Bar"}});
//
// where `MySuite` is an identifier for a group of related tests, and
// `CallingMyApiNeverCrashes` is the name of the test and also the name of the
// "property function". The property function can have any number of parameters.
// The input domain of each parameter can be assigned using `.WithDomains()`,
// and the initial seed values can be provided using `.WithSeeds()`.
//
// When each parameter's input domain is `Arbitrary<T>()`, which allows any
// value of a given type T, i.e.:
//
//   FUZZ_TEST(MySuite, CallingMyApiNeverCrashes)
//     .WithDomains(/*x:*/fuzztest::Arbitrary<int>(),
//                  /*s:*/fuzztest::Arbitrary<std::string>());
//
// then the input domain assignment with `.WithDomains()` can be omitted:
//
//   FUZZ_TEST(MySuite, CallingMyApiNeverCrashes);
//
// Note: When specifying both the domains and seeds, the domain clause has to
// be specified first.
#define FUZZ_TEST(suite_name, func) INTERNAL_FUZZ_TEST(suite_name, func)

// The FUZZ_TEST_F macro registers a fuzz test that uses a test fixture.
//
// The first parameter is the name of the fixture class, which is also used as
// the name of the test suite. The second parameter is the name of the property
// function (also used as the test name), which must be defined as a public
// member of the fixture class.
//
// A test fixture can be any default-constructible class. The fixture's setup
// code should be in its constructor, and the teardown code should be in its
// destructor. While running the fuzz test, which involves calling the property
// function multiple times with various inputs, the fixture will be instantiated
// only once at the beginning and destroyed at the end of the fuzz test. In
// particular, the same instance will be used in all calls to the property
// function.
//
// If the fixture you are using is a GoogleTest fixture (i.e., it extends
// `::testing::Test`, either directly or indirectly), then you will additionally
// need to wrap the fixture in an adapter. For more details, see
// https://github.com/google/fuzztest/blob/main/doc/fixtures.md.
//
// Just like the FUZZ_TEST macro, the FUZZ_TEST_F macro allows specifying the
// domains and seeds using the `.WithDomains()` and `.WithSeeds()` clauses.
//
// Example:
//
//   class FooFuzzTest {
//    public:
//     FooFuzzTest() { foo_.SetUp(); }
//     ~FooFuzzTest() { foo_.TearDown(); }
//
//     void CallingFooBarNeverCrashes(int x, const std::string& s) {
//       bool result = foo_.Bar(x, s);
//       ASSERT_TRUE(result);
//     }
//
//    private:
//     Foo foo_;
//   };
//   FUZZ_TEST_F(FooFuzzTest, CallingFooBarNeverCrashes)
//     .WithDomains(/*x:*/fuzztest::Positive<int>(),
//                  /*s:*/fuzztest::AsciiString())
//     .WithSeeds({{5, "Foo"}, {10, "Bar"}});
//
#define FUZZ_TEST_F(fixture, func) \
  INTERNAL_FUZZ_TEST_F(fixture, func, fixture, func)

// Reads files as strings from the directory `dir` and returns a vector usable
// by .WithSeeds().
//
// Example:
//
//   void MyThingNeverCrashes(const std::string& s) {
//     DoThingsWith(s);
//   }
//   FUZZ_TEST(MySuite, MyThingNeverCrashes)
//     .WithSeeds(ReadFilesFromDirectory(kCorpusPath));
std::vector<std::tuple<std::string>> ReadFilesFromDirectory(
    std::string_view dir);

}  // namespace fuzztest

// Temporarily disable fuzz tests under MSVC/iOS/MacOS.
// They might not support all the C++17 features we are using right now.
// Disables all registration and disables running the domain expressions by
// using a ternary expression. The tail code (eg .WithDomains(...)) will not be
// executed.
#if defined(__APPLE__) || defined(_MSC_VER)
#undef FUZZ_TEST
#define FUZZ_TEST(suite_name, func)                          \
  [[maybe_unused]] static ::fuzztest::internal::RegisterStub \
      fuzztest_reg_##suite_name##func =                      \
          true ? ::fuzztest::internal::RegisterStub()        \
               : ::fuzztest::internal::RegisterStub()
#endif  // defined(__APPLE__) || defined(_MSC_VER)

#endif  // FUZZTEST_FUZZTEST_FUZZTEST_H_
