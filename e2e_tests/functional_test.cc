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

#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "absl/time/time.h"
#include "./fuzztest/internal/io.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/subprocess.h"
#include "./fuzztest/internal/type_support.h"
#include "re2/re2.h"

namespace fuzztest::internal {
namespace {

using ::testing::_;
using ::testing::AllOf;
using ::testing::AnyOf;
using ::testing::ContainsRegex;
using ::testing::Eq;
using ::testing::FieldsAre;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::IsSubsetOf;
using ::testing::Le;
using ::testing::Ne;
using ::testing::Not;
using ::testing::Optional;
using ::testing::SizeIs;
using ::testing::StartsWith;

constexpr absl::string_view kDefaultTargetBinary =
    "testdata/fuzz_tests_for_functional_testing";

std::string BinaryPath(const absl::string_view name) {
  const auto test_srcdir = absl::NullSafeStringView(getenv("TEST_SRCDIR"));
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(
      !test_srcdir.empty(),
      "Please set TEST_SRCDIR to non-empty value or use bazel to run the "
      "test.");
  const std::string binary_path = absl::StrCat(
      test_srcdir, "/com_google_fuzztest/e2e_tests/", name,
      absl::EndsWith(name, ".stripped") ? "" : ".stripped");

  FUZZTEST_INTERNAL_CHECK(std::filesystem::exists(binary_path),
                          absl::StrCat("Can't find ", binary_path));
  return binary_path;
}

class TempDir {
 public:
  TempDir() {
    dirname_ = "/tmp/replay_test_XXXXXX";
    dirname_ = mkdtemp(dirname_.data());
    EXPECT_TRUE(std::filesystem::is_directory(dirname_));
  }

  const std::string& dirname() const { return dirname_; }

  ~TempDir() { std::filesystem::remove_all(dirname_); }

 private:
  std::string dirname_;
};

class UnitTestModeTest : public ::testing::Test {
 protected:
  void SetUp() override {
#ifdef FUZZTEST_USE_CENTIPEDE
    GTEST_SKIP() << "Skipping the unit test mode tests in the Centipede based "
                    "multi-process configuration. Please run with "
                    "--config=fuzztest to enable these tests!";
#endif
  }

  RunResults Run(
      std::string_view test_filter,
      std::string_view target_binary = kDefaultTargetBinary,
      const absl::flat_hash_map<std::string, std::string>& env = {}) {
    return RunCommand(
        {BinaryPath(target_binary),
         absl::StrCat("--", GTEST_FLAG_PREFIX_, "filter=", test_filter)},
        env, absl::Minutes(10));
  }
};

TEST_F(UnitTestModeTest, PassingTestPassesInUnitTestingMode) {
  auto [status, std_out, std_err] = Run("MySuite.PassesWithPositiveInput");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, InvalidSeedsAreSkippedAndReported) {
  auto [status, std_out, std_err] =
      Run(/*test_filter=*/"*",
          /*target_binary=*/"testdata/fuzz_tests_with_invalid_seeds");
  EXPECT_THAT(std_err, HasSubstr("[!] Skipping WithSeeds() value in"));
  EXPECT_THAT(std_err,
              HasSubstr("Could not turn value into corpus type:\n{17}"));
  EXPECT_THAT(std_err, HasSubstr("The value 17 is not InRange(0, 10):\n{17}"));
  // Valid seeds are not reported.
  EXPECT_THAT(std_err, Not(HasSubstr("{6}")));
  // Tests should still run.
  EXPECT_THAT(std_out, HasSubstr("[  PASSED  ] 3 tests."));
  EXPECT_THAT(status, ExitCode(0));
}

TEST_F(UnitTestModeTest, CorpusIsMutatedInUnitTestMode) {
  auto [status, std_out, std_err] = Run("MySuite.PassesString");
  EXPECT_THAT(std_err, HasSubstr("==<<Saw size=0>>=="));
  EXPECT_THAT(std_err, HasSubstr("==<<Saw size=1>>=="));
  EXPECT_THAT(std_err, HasSubstr("==<<Saw size=2>>=="));
  EXPECT_THAT(std_err, HasSubstr("==<<Saw size=3>>=="));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, UnitTestModeLimitsNumberOfIterationsByWallTime) {
  // We run this in unittest mode to check that we reduce the number of
  // iterations to accommodate for the longer run time.
  auto [status, std_out, std_err] = Run("MySuite.OneIterationTakesTooMuchTime");
  EXPECT_THAT(std_out,
              HasSubstr("[       OK ] MySuite.OneIterationTakesTooMuchTime"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

int CountSubstrs(std::string_view haystack, std::string_view needle) {
  int count = 0;
  while (true) {
    size_t pos = haystack.find(needle);
    if (pos == haystack.npos) return count;
    ++count;
    haystack.remove_prefix(pos + needle.size());
  }
}

RE2 MakeReproducerRegex(absl::string_view suite_name,
                        absl::string_view test_name, absl::string_view args) {
  return RE2(
      absl::Substitute(R"re(TEST\($0, $1.*\) {\n.*$1\(\n.*$2.*\n.*\).*\n.*})re",
                       suite_name, test_name, args));
}

std::string RemoveReproducer(std::string str, absl::string_view suite_name,
                             absl::string_view test_name,
                             absl::string_view args) {
  EXPECT_TRUE(
      RE2::Replace(&str, MakeReproducerRegex(suite_name, test_name, args), ""));
  return str;
}

// Matches strings that contain a reproducer test.
//
// For example, `HasReproducerTest("MySuite", "MyTest", "1, \"foo\"")` would
// match the following string:
//
//   TEST(MySuite, MyTestRegression) {
//     MyTest(
//       1, "foo"
//     );
//   }
//
// The parameters `suite_name`, `test_name`, and `args` are regular expressions;
// make sure they are properly escaped!
MATCHER_P3(HasReproducerTest, suite_name, test_name, args, "") {
  // `ContainsRegex` doesn't support the following regex externally.
  return RE2::PartialMatch(arg,
                           MakeReproducerRegex(suite_name, test_name, args));
}

void GoogleTestExpectationsDontAbortInUnitTestModeImpl(
    const RunResults& run_results) {
  const auto& [status, std_out, std_err] = run_results;
  EXPECT_THAT(std_err, HasSubstr("argument 0: ")) << std_err;
  // We expect both to run without crashing.
  EXPECT_THAT(std_out, HasSubstr("[  FAILED  ] MySuite.GoogleTestExpect"))
      << std_out;
  EXPECT_THAT(std_out, HasSubstr("[  FAILED  ] MySuite.GoogleTestAssert"))
      << std_out;
  EXPECT_THAT(status, Ne(ExitCode(0)));

  // There is no repro example on stdout, and there is one on stderr.
  EXPECT_THAT(
      std_out,
      AllOf(Not(HasReproducerTest("MySuite", "GoogleTestExpect", ".*")),
            Not(HasReproducerTest("MySuite", "GoogleTestAssert", ".*"))));
  EXPECT_THAT(std_err,
              AllOf(HasReproducerTest("MySuite", "GoogleTestExpect", ".*"),
                    HasReproducerTest("MySuite", "GoogleTestAssert", ".*")));
}

TEST_F(UnitTestModeTest, GoogleTestExpectationsDontAbortInUnitTestMode) {
  GoogleTestExpectationsDontAbortInUnitTestModeImpl(
      Run("MySuite.GoogleTestExpect:MySuite.GoogleTestAssert"));
}

TEST_F(UnitTestModeTest,
       GoogleTestExpectationsDontAbortInUnitTestModeWhenAsanHandlesAbort) {
  GoogleTestExpectationsDontAbortInUnitTestModeImpl(Run(
      "MySuite.GoogleTestExpect:MySuite.GoogleTestAssert", kDefaultTargetBinary,
      /*env=*/{{"ASAN_OPTIONS", "handle_abort=2"}}));
}

TEST_F(UnitTestModeTest, GlobalEnvironmentGoesThroughCompleteLifecycle) {
  auto [status, std_out, std_err] = Run("MySuite.GoogleTestExpect");
  EXPECT_EQ(
      1, CountSubstrs(std_err, "<<GlobalEnvironment::GlobalEnvironment()>>"));
  EXPECT_EQ(1, CountSubstrs(std_err, "<<GlobalEnvironment::SetUp()>>"));
  EXPECT_EQ(1, CountSubstrs(std_err, "<<GlobalEnvironment::TearDown()>>"));
  EXPECT_EQ(
      1, CountSubstrs(std_err, "<<GlobalEnvironment::~GlobalEnvironment()>>"));
}

TEST_F(UnitTestModeTest, FixtureGoesThroughCompleteLifecycle) {
  auto [status, std_out, std_err] = Run("FixtureTest.NeverFails");
  EXPECT_EQ(1, CountSubstrs(std_err, "<<FixtureTest::FixtureTest()>>"));
  EXPECT_EQ(1, CountSubstrs(std_err, "<<FixtureTest::~FixtureTest()>>"));
}

TEST_F(UnitTestModeTest,
       GoogleTestPerIterationFixtureInstantiatedOncePerIteration) {
  auto [status, std_out, std_err] =
      Run("CallCountPerIteration.CallCountIsAlwaysIncrementedFromInitialValue");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest,
       GoogleTestPerFuzzTestFixtureInstantiatedOncePerFuzzTest) {
  auto [status, std_out, std_err] =
      Run("CallCountPerFuzzTest.CallCountReachesAtLeastTen");
  EXPECT_EQ(
      1, CountSubstrs(std_err, "<<CallCountGoogleTest::call_count_ == 10>>"));
}

TEST_F(UnitTestModeTest, GoogleTestStaticTestSuiteFunctionsCalledOnce) {
  auto [status, std_out, std_err] =
      Run("CallCountPerFuzzTest.CallCountReachesAtLeastTen:"
          "CallCountPerFuzzTest.NeverFails");
  EXPECT_EQ(1,
            CountSubstrs(std_err, "<<CallCountGoogleTest::SetUpTestSuite()>>"));
  EXPECT_EQ(
      1, CountSubstrs(std_err, "<<CallCountGoogleTest::TearDownTestSuite()>>"));
}

TEST_F(UnitTestModeTest, GoogleTestWorksWithProtoExtensionsUsedInSeeds) {
  auto [status, std_out, std_err] = Run("MySuite.CheckProtoExtensions");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("Uses proto extensions"));
}

TEST_F(UnitTestModeTest, UnitTestAndFuzzTestCanShareSuiteName) {
  auto [status, std_out, std_err] =
      Run("SharedSuite.WorksAsUnitTest:SharedSuite.WorksAsFuzzTest");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, RepeatedFieldsHaveMinSizeWhenInitialized) {
  auto [status, std_out, std_err] = Run("MySuite.RepeatedFieldHasMinimumSize");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, OptionalProtoFieldCanHaveNoValue) {
  auto [status, std_out, std_err] = Run("MySuite.FailsWhenFieldI32HasNoValue");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(UnitTestModeTest, OptionalProtoFieldThatIsUnsetNeverHasValue) {
  auto [status, std_out, std_err] = Run("MySuite.FailsWhenFieldI64HasValue");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, ProtoFieldsThatAreUnsetNeverHaveValue) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsWhen64IntegralFieldsHaveValues");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest,
       ProtoFieldThatAreCustomizedAndAlwaysSetHaveCorrectValue) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsWhenFieldsOfTypeDoubleHasNoValue");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, ProtoFieldsThatAreAlwaysSetAlwaysHaveValue) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsWhen64IntegralFieldsHaveNoValues");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, CanCustomizeProtoFieldsWithTransformers) {
  auto [status, std_out, std_err] =
      Run("MySuite."
          "FailsIfRepeatedEnumsHaveZeroValueAndOptionalEnumHasNonZeroValue");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest,
       RequiredProtoFieldWillBeSetWhenNullnessIsNotCustomized) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsWhenRequiredInt32FieldHasNoValue");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, RequiredProtoFieldThatIsNotAlwaysSetCanHaveNoValue) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsWhenRequiredEnumFieldHasNoValue");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("cannot have null values"));
}

TEST_F(UnitTestModeTest, OptionalProtoFieldThatIsNotAlwaysSetCanHaveNoValue) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsWhenOptionalFieldU32HasNoValue");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(UnitTestModeTest, ProtobufOfMutatesTheProto) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsWhenI32ContainsTheSecretNumber");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("Secret number is found"));
}

TEST_F(UnitTestModeTest, ProtobufEnumEqualsLabel4) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsIfProtobufEnumEqualsLabel4");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(
      std_err,
      HasSubstr("argument 0: fuzztest::internal::TestProtobuf::Label4"));
}

TEST_F(UnitTestModeTest, WorksWithRecursiveStructs) {
  auto [status, std_out, std_err] = Run("MySuite.WorksWithRecursiveStructs");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  // Nullptr has multiple possible human-readable representations.
  EXPECT_THAT(std_err, AnyOf(HasSubstr("argument 0: {0, 1}"),
                             HasSubstr("argument 0: {(nil), 1}")));
}

TEST_F(UnitTestModeTest, WorksWithStructsWithConstructors) {
  auto [status, std_out, std_err] =
      Run("MySuite.WorksWithStructsWithConstructors");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("argument 0: {1, \"abc\"}"));
}

TEST_F(UnitTestModeTest, WorksWithStructsWithEmptyTuples) {
  auto [status, std_out, std_err] =
      Run("MySuite.WorksWithStructsWithEmptyTuples");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("argument 0: {}"));
}

TEST_F(UnitTestModeTest, WorksWithEmptyStructs) {
  auto [status, std_out, std_err] = Run("MySuite.WorksWithEmptyStructs");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("argument 0: {}"));
}

TEST_F(UnitTestModeTest, WorksWithStructsWithEmptyFields) {
  auto [status, std_out, std_err] =
      Run("MySuite.WorksWithStructsWithEmptyFields");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("argument 0: {{}}"));
}

TEST_F(UnitTestModeTest, WorksWithEmptyInheritance) {
  auto [status, std_out, std_err] = Run("MySuite.WorksWithEmptyInheritance");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("argument 0: {0, \"abc\"}"));
}

TEST_F(UnitTestModeTest, ArbitraryWorksWithEmptyInheritance) {
  auto [status, std_out, std_err] =
      Run("MySuite.ArbitraryWorksWithEmptyInheritance");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("argument 0:"));
}

TEST_F(UnitTestModeTest, FlatMapCorrectlyPrintsValues) {
  auto [status, std_out, std_err] = Run("MySuite.FlatMapCorrectlyPrintsValues");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  // This is the argument to the output domain.
  EXPECT_THAT(std_err, HasSubstr("argument 0: {\"AAA\", \"BBB\"}"));
  // This is the argument to the input domain.
  EXPECT_THAT(std_err, Not(HasSubstr("argument 0: 3")));
}

TEST_F(UnitTestModeTest, PropertyFunctionAcceptsTupleOfItsSingleParameter) {
  auto [status, std_out, std_err] = Run("MySuite.UnpacksTupleOfOne");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(UnitTestModeTest, PropertyFunctionAcceptsTupleOfItsThreeParameters) {
  auto [status, std_out, std_err] = Run("MySuite.UnpacksTupleOfThree");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(UnitTestModeTest, PropertyFunctionAcceptsTupleContainingTuple) {
  auto [status, std_out, std_err] = Run("MySuite.UnpacksTupleContainingTuple");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(UnitTestModeTest, ProtoFieldsCanBeAlwaysSet) {
  auto [status, std_out, std_err] = Run("MySuite.FailsWhenSubprotoIsNull");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, ProtoFieldsCanBeUnset) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsWhenSubprotoFieldsAreSet");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, RepeatedProtoFieldsCanBeCustomized) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsWhenRepeatedSubprotoIsSmallOrHasAnEmptyElement");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, DefaultOptionalPolicyAppliesToAllOptionalFields) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsWhenAnyOptionalFieldsHaveValue");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(
    UnitTestModeTest,
    DefaultOptionalPolicyAppliesToAllOptionalFieldsWithoutOverwrittenDomain) {
  auto [status, std_out, std_err] = Run(
      "MySuite."
      "FailsWhenAnyOptionalFieldsHaveValueButNotFieldsWithOverwrittenDomain");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(
    UnitTestModeTest,
    DefaultOptionalPolicyAppliesToAllOptionalFieldsWithoutOverwrittenPolicy) {
  auto [status, std_out, std_err] = Run(
      "MySuite."
      "FailsWhenAnyOptionalFieldsHaveValueButNotFieldsWithOverwrittenPolicy");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, DetectsRecursiveStructureIfOptionalsSetByDefault) {
  auto [status, std_out, std_err] = Run("MySuite.FailsIfCantInitializeProto");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("recursive fields"));
}

TEST_F(UnitTestModeTest,
       AvoidsFailureIfSetByDefaultPolicyIsOverwrittenOnRecursiveStructures) {
  auto [status, std_out, std_err] =
      Run("MySuite."
          "InitializesRecursiveProtoIfInfiniteRecursivePolicyIsOverwritten");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest,
       DefaultRepeatedFieldsMinSizeAppliesToAllRepeatedFields) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsIfRepeatedFieldsDontHaveTheMinimumSize");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest,
       DefaultRepeatedFieldsMaxSizeAppliesToAllRepeatedFields) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsIfRepeatedFieldsDontHaveTheMaximumSize");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, FailsWhenRepeatedFieldsSizeRangeIsInvalid) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsToInitializeIfRepeatedFieldsSizeRangeIsInvalid");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("size range is not valid"));
}

TEST_F(UnitTestModeTest, UsesPolicyProvidedDefaultDomainForProtos) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsWhenSubprotosDontSetOptionalI32");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, ChecksTypeOfProvidedDefaultDomainForProtos) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsWhenWrongDefaultProtobufDomainIsProvided");
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("does not match the expected message type"));
}

TEST_F(UnitTestModeTest, PoliciesApplyToFieldsInOrder) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsWhenI32FieldValuesDontRespectAllPolicies");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(UnitTestModeTest, AlwaysSetAndUnsetWorkOnOneofFields) {
  auto [status, std_out, std_err] =
      Run("MySuite.FailsWhenOneofFieldDoesntHaveOneofValue");
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

// Tests for the FuzzTest command line interface.
class GenericCommandLineInterfaceTest : public ::testing::Test {
 protected:
  void SetUp() override {
#ifdef FUZZTEST_USE_CENTIPEDE
    GTEST_SKIP() << "Skipping the FuzzTest command line interface tests in the "
                    "Centipede based multi-process configuration. Please run "
                    "with --config=fuzztest to enable these tests!";
#endif
  }

  RunResults RunWith(
      std::string_view flags,
      const absl::flat_hash_map<std::string, std::string>& env = {},
      absl::Duration timeout = absl::Minutes(10)) {
    std::vector<std::string> args = {BinaryPath(kDefaultTargetBinary)};
    std::vector<std::string> split_flags = absl::StrSplit(flags, ' ');
    args.insert(args.end(), split_flags.begin(), split_flags.end());
    return RunCommand(args, env, timeout);
  }
};

TEST_F(GenericCommandLineInterfaceTest, FuzzTestsAreFoundInTheBinary) {
  auto [status, std_out, std_err] = RunWith("--list_fuzz_tests");
  EXPECT_THAT(std_out, HasSubstr("[*] Fuzz test: MySuite.Coverage"));
  EXPECT_THAT(std_out, HasSubstr("[*] Fuzz test: MySuite.DivByZero"));
  EXPECT_THAT(std_out,
              HasSubstr("[*] Fuzz test: MySuite.PassesWithPositiveInput"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

// Tests for the FuzzTest command line interface in fuzzing mode, which can only
// run with coverage instrumentation enabled.
class FuzzingModeCommandLineInterfaceTest
    : public GenericCommandLineInterfaceTest {
 protected:
  void SetUp() override {
    GenericCommandLineInterfaceTest::SetUp();
#if defined(__has_feature)
#if !__has_feature(coverage_sanitizer)
    GTEST_SKIP() << "No coverage instrumentation: skipping the fuzzing mode "
                    "command line interface tests. "
                    "Please run with --config=fuzztest to enable these tests!";
#endif
#endif
  }
};

TEST_F(FuzzingModeCommandLineInterfaceTest, WrongFuzzTestNameTriggersError) {
  auto [status, std_out, std_err] = RunWith("--fuzz=WrongName");
  EXPECT_THAT(std_err, HasSubstr("No FUZZ_TEST matches the name: WrongName"));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST_F(FuzzingModeCommandLineInterfaceTest,
       MatchingMultipleFuzzTestsTriggersError) {
  auto [status, std_out, std_err] = RunWith("--fuzz=Bad");
  EXPECT_THAT(
      std_err,
      HasSubstr(
          "Multiple FUZZ_TESTs match the name: Bad\n\nPlease select one. "
          "Matching tests:\n MySuite.BadFilter\n MySuite.BadWithMinSize\n"));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST_F(FuzzingModeCommandLineInterfaceTest, RunsAbortTestAndDetectsAbort) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.Aborts");
  EXPECT_THAT(std_err, HasSubstr("argument 0: "));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeCommandLineInterfaceTest,
       FuzzTestCanBeSelectedForFuzzingUsingSubstring) {
  auto [status, std_out, std_err] = RunWith("--fuzz=Abort");
  EXPECT_THAT(std_err, HasSubstr("argument 0: "));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeCommandLineInterfaceTest,
       IgnoresNegativeFuzzingRunsLimitInEnvVar) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.PassesWithPositiveInput",
              {{"FUZZTEST_MAX_FUZZING_RUNS", "-1"}},
              /*timeout=*/absl::Seconds(1));
  EXPECT_THAT(std_err, HasSubstr("will not limit fuzzing runs")) << std_err;
}

TEST_F(FuzzingModeCommandLineInterfaceTest, LimitsFuzzingRunsWhenEnvVarIsSet) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.PassesWithPositiveInput",
              {{"FUZZTEST_MAX_FUZZING_RUNS", "100"}});
  EXPECT_THAT(std_err,
              // 100 fuzzing runs + 1 seed run.
              HasSubstr("Total runs: 101"))
      << std_err;
}

TEST_F(FuzzingModeCommandLineInterfaceTest, LimitsFuzzingRunsWhenTimeoutIsSet) {
  auto [status, std_out, std_err] = RunWith(
      "--fuzz=MySuite.PassesWithPositiveInput --fuzz_for=1s");
  EXPECT_THAT(std_err, HasSubstr("Fuzzing timeout set to: 1s")) << std_err;
}

TEST_F(FuzzingModeCommandLineInterfaceTest, ReproducerIsDumpedWhenEnvVarIsSet) {
  TempDir out_dir;

  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.String",
              {{"FUZZTEST_REPRODUCERS_OUT_DIR", out_dir.dirname()}});
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"Fuzz"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));

  auto replay_files = ReadFileOrDirectory(out_dir.dirname());
  ASSERT_EQ(replay_files.size(), 1) << std_err;
  auto parsed = IRObject::FromString(replay_files[0].data);
  ASSERT_TRUE(parsed) << std_err;
  auto args = parsed->ToCorpus<std::tuple<std::string>>();
  EXPECT_THAT(args, Optional(FieldsAre(StartsWith("Fuzz")))) << std_err;
}

TEST_F(FuzzingModeCommandLineInterfaceTest, SavesCorpusWhenEnvVarIsSet) {
  TempDir out_dir;
  // We cannot use a non-crashing test since there is no easy way to limit the
  // run time here.
  //
  // Although theoretically possible, it is extreme unlikely that the test would
  // find the crash without saving some corpus.
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.String",
              {{"FUZZTEST_TESTSUITE_OUT_DIR", out_dir.dirname()}});

  auto corpus_files = ReadFileOrDirectory(out_dir.dirname());
  EXPECT_THAT(corpus_files, Not(IsEmpty())) << std_err;
}

TEST_F(FuzzingModeCommandLineInterfaceTest, RestoresCorpusWhenEnvVarIsSet) {
  TempDir corpus_dir;
  // We cannot use a non-crashing test since there is no easy way to limit the
  // run time here.
  //
  // Although theoretically possible, it is extreme unlikely that the test would
  // find the crash without saving some corpus.
  auto [producer_status, producer_std_out, producer_std_err] =
      RunWith("--fuzz=MySuite.String",
              {{"FUZZTEST_TESTSUITE_OUT_DIR", corpus_dir.dirname()}});

  auto corpus_files = ReadFileOrDirectory(corpus_dir.dirname());
  ASSERT_THAT(corpus_files, Not(IsEmpty())) << producer_std_err;

  auto [consumer_status, consumer_std_out, consumer_std_err] =
      RunWith("--fuzz=MySuite.String",
              {{"FUZZTEST_TESTSUITE_IN_DIR", corpus_dir.dirname()}});
  EXPECT_THAT(consumer_std_err,
              HasSubstr(absl::StrFormat("Parsed %d inputs and ignored 0 inputs",
                                        corpus_files.size())));
}

TEST_F(FuzzingModeCommandLineInterfaceTest, MinimizesCorpusWhenEnvVarIsSet) {
  TempDir corpus_dir;
  TempDir minimized_corpus_dir;
  // We cannot use a non-crashing test since there is no easy way to limit the
  // run time here.
  //
  // Although theoretically possible, it is extreme unlikely that the test would
  // find the crash without saving some corpus.
  auto [producer_status, producer_std_out, producer_std_err] =
      RunWith("--fuzz=MySuite.String",
              {{"FUZZTEST_TESTSUITE_OUT_DIR", corpus_dir.dirname()}});

  auto corpus_files = ReadFileOrDirectory(corpus_dir.dirname());
  ASSERT_THAT(corpus_files, Not(IsEmpty())) << producer_std_err;
  std::vector<std::string> corpus_data;
  for (const FilePathAndData& corpus_file : corpus_files) {
    corpus_data.push_back(corpus_file.data);
  }

  auto [minimizer_status, minimizer_std_out, minimizer_std_err] =
      RunWith("--fuzz=MySuite.String",
              {{"FUZZTEST_MINIMIZE_TESTSUITE_DIR", corpus_dir.dirname()},
               {"FUZZTEST_TESTSUITE_OUT_DIR", minimized_corpus_dir.dirname()}});

  auto minimized_corpus_files =
      ReadFileOrDirectory(minimized_corpus_dir.dirname());
  EXPECT_THAT(minimized_corpus_files,
              AllOf(Not(IsEmpty()), SizeIs(Le(corpus_files.size()))))
      << minimizer_std_err;
  std::vector<std::string> minimized_corpus_data;
  for (const FilePathAndData& minimized_corpus_file : minimized_corpus_files) {
    minimized_corpus_data.push_back(minimized_corpus_file.data);
  }
  EXPECT_THAT(minimized_corpus_data, IsSubsetOf(corpus_data));

  EXPECT_THAT(
      minimizer_std_err,
      AllOf(HasSubstr(absl::StrFormat("Parsed %d inputs and ignored 0 inputs",
                                      corpus_files.size())),
            HasSubstr(absl::StrFormat(
                "Selected %d corpus inputs in minimization mode",
                minimized_corpus_files.size()))));
}

TEST_F(FuzzingModeCommandLineInterfaceTest, MinimizesDuplicatedCorpus) {
  TempDir corpus_dir;
  TempDir minimized_corpus_dir;
  // We cannot use a non-crashing test since there is no easy way to limit the
  // run time here.
  //
  // Although theoretically possible, it is extreme unlikely that the test would
  // find the crash without saving some corpus.
  auto [producer_status, producer_std_out, producer_std_err] =
      RunWith("--fuzz=MySuite.String",
              {{"FUZZTEST_TESTSUITE_OUT_DIR", corpus_dir.dirname()}});

  auto corpus_files = ReadFileOrDirectory(corpus_dir.dirname());
  ASSERT_THAT(corpus_files, Not(IsEmpty())) << producer_std_err;
  for (const auto& corpus_file : corpus_files) {
    ASSERT_TRUE(WriteFile(corpus_file.path + "_dup", corpus_file.data));
  }

  auto [minimizer_status, minimizer_std_out, minimizer_std_err] =
      RunWith("--fuzz=MySuite.String",
              {{"FUZZTEST_MINIMIZE_TESTSUITE_DIR", corpus_dir.dirname()},
               {"FUZZTEST_TESTSUITE_OUT_DIR", minimized_corpus_dir.dirname()}});

  auto minimized_corpus_files =
      ReadFileOrDirectory(minimized_corpus_dir.dirname());
  EXPECT_THAT(minimized_corpus_files,
              AllOf(Not(IsEmpty()), SizeIs(Le(corpus_files.size()))))
      << minimizer_std_err;

  EXPECT_THAT(
      minimizer_std_err,
      AllOf(HasSubstr(absl::StrFormat("Parsed %d inputs and ignored 0 inputs",
                                      corpus_files.size() * 2)),
            // TODO(b/207375007): Due to non-determinism, sometimes duplicated
            // input can reach new coverage and thus be counted into the corpus
            // (but not reflected in the files since they are
            // content-addressed). We use AnyOf to mitigate the flakiness.
            AnyOf(HasSubstr(absl::StrFormat(
                      "Selected %d corpus inputs in minimization mode",
                      minimized_corpus_files.size())),
                  HasSubstr(absl::StrFormat(
                      "Selected %d corpus inputs in minimization mode",
                      minimized_corpus_files.size() + 1)),
                  HasSubstr(absl::StrFormat(
                      "Selected %d corpus inputs in minimization mode",
                      minimized_corpus_files.size() + 2)))));
}

class ReplayFile {
 public:
  template <typename T>
  ReplayFile(std::in_place_t, const T& corpus) {
    filename_ = absl::StrCat(dir_.dirname(), "/replay_file");
    WriteFile(filename_, internal::IRObject::FromCorpus(corpus).ToString());
  }

  auto GetReplayEnv() const {
    return absl::flat_hash_map<std::string, std::string>{
        {"FUZZTEST_REPLAY", filename_}};
  }

  auto GetMinimizeEnv() const {
    return absl::flat_hash_map<std::string, std::string>{
        {"FUZZTEST_MINIMIZE_REPRODUCER", filename_}};
  }

 private:
  TempDir dir_;
  std::string filename_;
};

TEST_F(FuzzingModeCommandLineInterfaceTest,
       ReplayingNonCrashingReproducerDoesNotCrash) {
  ReplayFile replay(std::in_place, std::tuple<std::string>{"NotFuzz"});

  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.String", replay.GetReplayEnv());
  EXPECT_THAT(status, Eq(ExitCode(0))) << std_err;
}

TEST_F(FuzzingModeCommandLineInterfaceTest,
       ReplayingCrashingReproducerCrashes) {
  ReplayFile replay(std::in_place,
                    std::tuple<std::string>{"Fuzz with some tail."});

  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.String", replay.GetReplayEnv());
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"Fuzz with some tail.\""));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

// The TypeErased tests below try the same as above, but with Domain<T> domains
// to makes sure the type erasure of the corpus_type can be correctly
// serialized.
TEST_F(FuzzingModeCommandLineInterfaceTest,
       ReproducerIsDumpedWhenEnvVarIsSetTypeErased) {
  TempDir out_dir;

  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.WithDomainClass",
              {{"FUZZTEST_REPRODUCERS_OUT_DIR", out_dir.dirname()}});
  EXPECT_THAT(std_err, HasSubstr("argument 0: 10")) << std_err;
  EXPECT_THAT(status, Ne(ExitCode(0))) << std_err;

  auto replay_files = ReadFileOrDirectory(out_dir.dirname());
  ASSERT_EQ(replay_files.size(), 1) << std_err;
  auto parsed = IRObject::FromString(replay_files[0].data);
  ASSERT_TRUE(parsed) << std_err;
  auto args = parsed->ToCorpus<std::tuple<uint8_t, double>>();
  EXPECT_THAT(args, Optional(FieldsAre(10, _))) << std_err;
}

TEST_F(FuzzingModeCommandLineInterfaceTest,
       ReplayingNonCrashingReproducerDoesNotCrashTypeErased) {
  ReplayFile replay(std::in_place, std::tuple<uint8_t, double>{11, 11});

  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.WithDomainClass", replay.GetReplayEnv());
  EXPECT_THAT(status, Eq(ExitCode(0))) << std_err;
}

TEST_F(FuzzingModeCommandLineInterfaceTest,
       ReplayingCrashingReproducerCrashesTypeErased) {
  ReplayFile replay(std::in_place, std::tuple<uint8_t, double>{10, 1979.125});
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.WithDomainClass", replay.GetReplayEnv());
  EXPECT_THAT(std_err, HasSubstr("argument 0: 10"));
  EXPECT_THAT(std_err, HasSubstr("argument 1: 1979.125"));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST_F(FuzzingModeCommandLineInterfaceTest, MinimizerFindsSmallerInput) {
  std::string current_input = "ABCXDEF";
  while (current_input != "X") {
    TempDir out_dir;
    ReplayFile replay(std::in_place, std::tuple<std::string>{current_input});
    auto env = replay.GetMinimizeEnv();
    env["FUZZTEST_REPRODUCERS_OUT_DIR"] = out_dir.dirname();

    auto [status, std_out, std_err] =
        RunWith("--fuzz=MySuite.Minimizer", env);
    ASSERT_THAT(std_err, HasSubstr("argument 0: \""));
    ASSERT_THAT(status, Eq(Signal(SIGABRT)));

    auto replay_files = ReadFileOrDirectory(out_dir.dirname());
    ASSERT_EQ(replay_files.size(), 1) << std_err;
    auto parsed = IRObject::FromString(replay_files[0].data);
    ASSERT_TRUE(parsed) << std_err;
    auto args = parsed->ToCorpus<std::tuple<std::string>>();
    ASSERT_THAT(args, Optional(FieldsAre(HasSubstr("X"))));
    std::string escaped;
    StringPrinter{}.PrintUserValue(std::get<0>(*args), &escaped,
                                   PrintMode::kHumanReadable);
    fprintf(stderr, "Found smaller case <%s>\n", escaped.c_str());
    current_input = std::get<0>(*args);
  }
}

TEST_F(FuzzingModeCommandLineInterfaceTest,
       FuzzerStatsArePrintedOnTermination) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.PassesWithPositiveInput",
              /*env=*/{},
              /*timeout=*/absl::Seconds(1));
  EXPECT_THAT(std_err, HasSubstr("Fuzzing was terminated"));
  EXPECT_THAT(std_err, HasSubstr("=== Fuzzing stats"));
  EXPECT_THAT(std_err, HasSubstr("Total runs:"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(FuzzingModeCommandLineInterfaceTest, SilenceTargetWorking) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.TargetPrintSomethingThenAbrt",
              /*env=*/{{"FUZZTEST_SILENCE_TARGET", "1"}});
  EXPECT_THAT(std_out, Not(HasSubstr("Hello World from target stdout")));
  EXPECT_THAT(std_err, HasSubstr("=== Fuzzing stats"));
  EXPECT_THAT(std_err, Not(HasSubstr("Hello World from target stderr")));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeCommandLineInterfaceTest, NonFatalFailureAllowsMinimization) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.NonFatalFailureAllowsMinimization");
  // The final failure should be with the known minimal result, even though many
  // "larger" inputs also trigger the failure.
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"0123\""));

  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeCommandLineInterfaceTest, GoogleTestHasCurrentTestInfo) {
  auto [status, std_out, std_err] = RunWith(
      "--fuzz=MySuite.GoogleTestHasCurrentTestInfo --fuzz_for=1s");
  EXPECT_THAT(std_out,
              HasSubstr("[       OK ] MySuite.GoogleTestHasCurrentTestInfo"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

#ifdef FUZZTEST_USE_CENTIPEDE
std::string CentipedePath() {
  const auto test_srcdir = absl::NullSafeStringView(getenv("TEST_SRCDIR"));
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(
      !test_srcdir.empty(),
      "Please set TEST_SRCDIR to non-empty value or use bazel to run the "
      "test.");
  const std::string binary_path = absl::StrCat(
      test_srcdir,
      "/com_google_fuzztest/centipede/centipede_uninstrumented");

  FUZZTEST_INTERNAL_CHECK(std::filesystem::exists(binary_path),
                          absl::StrCat("Can't find ", binary_path));
  return binary_path;
}
#endif

// Tests for the fixture logic in fuzzing mode, which can only run
// with coverage instrumentation enabled.
class FuzzingModeFixtureTest : public ::testing::Test {
 protected:
  void SetUp() override {
#if defined(__has_feature)
#if !__has_feature(coverage_sanitizer)
    GTEST_SKIP() << "No coverage instrumentation: skipping the fuzzing mode "
                    "fixture tests. "
                    "Please run with --config=fuzztest to enable these tests!";
#endif
#endif
  }

  RunResults Run(std::string_view test_name, int iterations) {
#ifdef FUZZTEST_USE_CENTIPEDE
    TempDir workdir;
    return RunCommand(
        {CentipedePath(), "--print_runner_log", "--exit_on_crash",
         absl::StrCat("--workdir=", workdir.dirname()),
         absl::StrCat("--binary=", BinaryPath(kDefaultTargetBinary), " ",
                      absl::StrCat("--fuzz=", test_name)),
         absl::StrCat("--num_runs=", iterations)},
        /*environment=*/{},
        /*timeout=*/absl::InfiniteDuration());
#else
    return RunCommand({BinaryPath(kDefaultTargetBinary),
                       absl::StrCat("--fuzz=", test_name)},
                      {{"FUZZTEST_MAX_FUZZING_RUNS", absl::StrCat(iterations)}},
                      /*timeout=*/absl::InfiniteDuration());
#endif
  }

  // Counts the number of times the target binary has been run. Needed because
  // Centipede runs the binary multiple times.
  int CountTargetRuns(std::string_view std_err) {
#ifdef FUZZTEST_USE_CENTIPEDE
    return CountSubstrs(std_err, "Centipede fuzz target runner; argv[0]:");
#else
    return 1;
#endif
  }
};

TEST_F(FuzzingModeFixtureTest, GlobalEnvironmentIsSetUpForFailingTest) {
  auto [status, std_out, std_err] =
      Run("MySuite.GoogleTestExpect", /*iterations=*/10);
  EXPECT_GT(CountTargetRuns(std_err), 0);
  EXPECT_EQ(
      CountTargetRuns(std_err),
      CountSubstrs(std_err, "<<GlobalEnvironment::GlobalEnvironment()>>"));
  EXPECT_EQ(CountTargetRuns(std_err),
            CountSubstrs(std_err, "<<GlobalEnvironment::SetUp()>>"));
}

TEST_F(FuzzingModeFixtureTest,
       GlobalEnvironmentGoesThroughCompleteLifecycleForSuccessfulTest) {
  auto [status, std_out, std_err] =
      Run("MySuite.GoogleTestNeverFails", /*iterations=*/10);
  EXPECT_GT(CountTargetRuns(std_err), 0);
  EXPECT_EQ(
      CountTargetRuns(std_err),
      CountSubstrs(std_err, "<<GlobalEnvironment::GlobalEnvironment()>>"));
  EXPECT_EQ(CountTargetRuns(std_err),
            CountSubstrs(std_err, "<<GlobalEnvironment::SetUp()>>"));
  EXPECT_EQ(CountTargetRuns(std_err),
            CountSubstrs(std_err, "<<GlobalEnvironment::TearDown()>>"));
  EXPECT_EQ(
      CountTargetRuns(std_err),
      CountSubstrs(std_err, "<<GlobalEnvironment::~GlobalEnvironment()>>"));
}

TEST_F(FuzzingModeFixtureTest, FixtureGoesThroughCompleteLifecycle) {
  auto [status, std_out, std_err] = Run("FixtureTest.NeverFails",
                                        /*iterations=*/10);
  EXPECT_GT(CountTargetRuns(std_err), 0);
  EXPECT_EQ(CountTargetRuns(std_err),
            CountSubstrs(std_err, "<<FixtureTest::FixtureTest()>>"));
  EXPECT_EQ(CountTargetRuns(std_err),
            CountSubstrs(std_err, "<<FixtureTest::~FixtureTest()>>"));
}

TEST_F(FuzzingModeFixtureTest,
       GoogleTestPerIterationFixtureInstantiatedOncePerIteration) {
  auto [status, std_out, std_err] =
      Run("CallCountPerIteration."
          "CallCountIsAlwaysIncrementedFromInitialValue",
          /*iterations=*/10);
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(FuzzingModeFixtureTest,
       GoogleTestPerFuzzTestFixtureInstantiatedOncePerFuzzTest) {
  auto [status, std_out, std_err] =
      Run("CallCountPerFuzzTest.CallCountReachesAtLeastTen", /*iterations=*/10);
  EXPECT_THAT(std_err, HasSubstr("<<CallCountGoogleTest::call_count_ == 10>>"));
}

TEST_F(FuzzingModeFixtureTest, GoogleTestStaticTestSuiteFunctionsCalledOnce) {
  auto [status, std_out, std_err] =
      Run("CallCountPerFuzzTest.CallCountReachesAtLeastTen", /*iterations=*/10);
  EXPECT_GT(CountTargetRuns(std_err), 0);
  EXPECT_EQ(CountTargetRuns(std_err),
            CountSubstrs(std_err, "<<CallCountGoogleTest::SetUpTestSuite()>>"));
  EXPECT_EQ(
      CountTargetRuns(std_err),
      CountSubstrs(std_err, "<<CallCountGoogleTest::TearDownTestSuite()>>"));
}

// Tests for the crash finding ability of the fuzzing mode, which can
// only run with coverage instrumentation enabled.
class FuzzingModeCrashFindingTest : public ::testing::Test {
 protected:
  void SetUp() override {
#if defined(__has_feature)
#if !__has_feature(coverage_sanitizer)
    GTEST_SKIP() << "No coverage instrumentation: skipping the fuzzing mode "
                    "crash finding tests. "
                    "Please run with --config=fuzztest to enable these tests!";
#endif
#endif
  }

  RunResults Run(std::string_view test_name,
                 std::string_view target_binary = kDefaultTargetBinary,
                 absl::Duration timeout = absl::InfiniteDuration()) {
    // We start the test binaries with an empty environment. This is
    // useful because we don't want to propagate env vars set by
    // Bazel, such as TEST_SHARD_INDEX, TEST_TOTAL_SHARDS,
    // TEST_PREMATURE_EXIT_FILE, TEST_WARNINGS_OUTPUT_FILE, etc. (See
    // https://bazel.build/reference/test-encyclopedia#initial-conditions.)
    // There are however env vars that we do want to propagate, which
    // we now need to do explicitly.
    absl::flat_hash_map<std::string, std::string> environment;
#ifdef FUZZTEST_USE_CENTIPEDE
    TempDir workdir;
    environment["ASAN_OPTIONS"] = "handle_aborts=0";
    return RunCommand({CentipedePath(), "--exit_on_crash",
                       absl::StrCat("--stop_at=", absl::Now() + timeout),
                       absl::StrCat("--workdir=", workdir.dirname()),
                       absl::StrCat("--binary=", BinaryPath(target_binary), " ",
                                    absl::StrCat("--fuzz=", test_name))},
                      environment, timeout + absl::Seconds(10));
#else
    return RunCommand(
        {BinaryPath(target_binary), absl::StrCat("--fuzz=", test_name)},
        environment, timeout);
#endif
  }
};

void ExpectTargetAbort(TerminationStatus status, std::string_view std_err) {
#ifdef FUZZTEST_USE_CENTIPEDE
  EXPECT_THAT(status, Ne(ExitCode(0)));
  EXPECT_TRUE(
      RE2::PartialMatch(std_err, absl::StrCat("Exit code\\s*:\\s*", SIGABRT)))
      << std_err;
#else
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
#endif
}

TEST_F(FuzzingModeCrashFindingTest,
       BufferOverflowIsDetectedWithStringViewInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.BufferOverreadWithStringView");
  EXPECT_THAT(
      std_err,
      AnyOf(HasSubstr("ERROR: AddressSanitizer: container-overflow"),
            HasSubstr("ERROR: AddressSanitizer: heap-buffer-overflow")));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST_F(FuzzingModeCrashFindingTest,
       DereferencingEmptyOptionalTriggersLibcppAssertionsWhenEnabled) {
#if defined(_LIBCPP_VERSION) && defined(_LIBCPP_ENABLE_ASSERTIONS)
  auto [status, std_out, std_err] = Run("MySuite.DereferenceEmptyOptional");
  EXPECT_THAT(std_err, HasSubstr("argument 0: std::nullopt"));
  ExpectTargetAbort(status, std_err);
#endif
}

TEST_F(FuzzingModeCrashFindingTest,
       BufferOverflowIsDetectedWithStringInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.BufferOverreadWithString");
  EXPECT_THAT(std_err,
              HasSubstr("ERROR: AddressSanitizer: heap-buffer-overflow"));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST_F(FuzzingModeCrashFindingTest,
       BufferOverflowIsDetectedWithStringAndLvalueStringViewRef) {
  auto [status, std_out, std_err] =
      Run("MySuite.BufferOverreadWithStringAndLvalueStringViewRef");
  EXPECT_THAT(std_err,
              HasSubstr("ERROR: AddressSanitizer: heap-buffer-overflow"));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST_F(FuzzingModeCrashFindingTest,
       BufferOverflowIsDetectedWithStringAndRvalueStringViewRef) {
  auto [status, std_out, std_err] =
      Run("MySuite.BufferOverreadWithStringAndRvalueStringViewRef");
  EXPECT_THAT(std_err,
              HasSubstr("ERROR: AddressSanitizer: heap-buffer-overflow"));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST_F(FuzzingModeCrashFindingTest, DivByZeroTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.DivByZero");
  EXPECT_THAT(std_err, HasSubstr("argument 1: 0"));
#ifdef ADDRESS_SANITIZER
  EXPECT_THAT(status, Ne(ExitCode(0)));
#else
  EXPECT_THAT(status, Eq(Signal(SIGFPE)));
#endif
}

TEST_F(FuzzingModeCrashFindingTest, CoverageTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.Coverage");
  EXPECT_THAT(std_err, HasSubstr("argument 0: 'F'"));
  EXPECT_THAT(std_err, HasSubstr("argument 1: 'u'"));
  EXPECT_THAT(std_err, HasSubstr("argument 2: 'z'"));
  EXPECT_THAT(std_err, HasSubstr("argument 3: 'z'"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, StringTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.String");
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"Fuzz"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest,
       StringAsciiOnlyTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.StringAsciiOnly");
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"Fuzz"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, StringRegexpTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.StringRegexp");
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"Fuzz"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, StringViewTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.StringView");
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"Fuzz"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, StrCmpTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.StrCmp");
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"Hello!"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, BitFlagsFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.BitFlags");
  EXPECT_THAT(std_err, HasSubstr("argument 0: 21"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, EnumTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.EnumValue");
  EXPECT_THAT(std_err, HasSubstr("argument 0: Color{0}"));
  EXPECT_THAT(std_err, HasSubstr("argument 1: Color{1}"));
  EXPECT_THAT(std_err, HasSubstr("argument 2: Color{2}"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, EnumClassTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.EnumClassValue");
  EXPECT_THAT(std_err, HasSubstr("argument 0: ColorClass{0}"));
  EXPECT_THAT(std_err, HasSubstr("argument 1: ColorClass{1}"));
  EXPECT_THAT(std_err, HasSubstr("argument 2: ColorClass{2}"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, ProtoTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.Proto");
  EXPECT_THAT(std_err, ContainsRegex(R"(argument 0: \(b:\s+true)"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, BitvectorValueTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.BitvectorValue");
  EXPECT_THAT(std_err, HasSubstr("argument 0: {true"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, VectorValueTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.VectorValue");
  EXPECT_THAT(std_err, HasSubstr("argument 0: {'F'"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest,
       FixedSizeVectorValueTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = Run("MySuite.FixedSizeVectorValue");
  EXPECT_THAT(std_err, HasSubstr("argument 0: {'F'"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, GoogleTestExpectationsStopTheFuzzer) {
  auto [status, std_out, std_err] = Run("MySuite.GoogleTestExpect");
  EXPECT_THAT(std_err, HasSubstr("argument 0: "));
  ExpectTargetAbort(status, std_err);

#ifndef FUZZTEST_USE_CENTIPEDE

  // There is the repro example only on stderr.
  EXPECT_THAT(std_out,
              Not(HasReproducerTest("MySuite", "GoogleTestExpect", ".*")));
#endif
  EXPECT_THAT(std_err, HasReproducerTest("MySuite", "GoogleTestExpect", ".*"));
}

TEST_F(FuzzingModeCrashFindingTest, GoogleTestAssertionsStopTheFuzzer) {
  auto [status, std_out, std_err] = Run("MySuite.GoogleTestAssert");
  EXPECT_THAT(std_err, HasSubstr("argument 0: "));
  ExpectTargetAbort(status, std_err);

#ifndef FUZZTEST_USE_CENTIPEDE

  // There is the repro example only on stderr.
  EXPECT_THAT(std_out,
              Not(HasReproducerTest("MySuite", "GoogleTestAssert", ".*")));

#endif
  EXPECT_THAT(std_err, HasReproducerTest("MySuite", "GoogleTestAssert", ".*"));
}

TEST_F(FuzzingModeCrashFindingTest, MappedDomainShowsMappedValue) {
  auto [status, std_out, std_err] = Run("MySuite.Mapping");
  EXPECT_THAT(
      std_err,
      AllOf(
          HasSubstr("argument 0: \"12 monkeys\""),
          HasReproducerTest(
              "MySuite", "Mapping",
              // Account for the possibility that the symbol
              // NumberOfAnimalsToString may be mangled.
              R"re(.*NumberOfAnimalsToString.*\(TimesTwo\(6\), "monkey"\))re")));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, FlatMappedDomainShowsMappedValue) {
  auto [status, std_out, std_err] = Run("MySuite.FlatMapping");
  EXPECT_THAT(std_err, AllOf(HasSubstr("argument 0: {\"abc\", 2}"),
                             HasReproducerTest(
                                 "MySuite", "FlatMapping",
                                 // Account for the possibility that the symbol
                                 // StringAndValidIndex may be mangled.
                                 R"re(.*StringAndValidIndex.*\("abc"\))re")));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, FlatMapPassesWhenCorrect) {
  auto [status, std_out, std_err] =
      Run("MySuite.FlatMapPassesWhenCorrect", kDefaultTargetBinary,
          /*timeout=*/absl::Seconds(1));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(FuzzingModeCrashFindingTest, FilterDomainShowsOnlyFilteredValues) {
  auto [status, std_out, std_err] = Run("MySuite.Filtering");
  EXPECT_THAT(std_err, HasSubstr("argument 0: 8"));
  EXPECT_THAT(std_err, HasSubstr("argument 1: 9"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, BadFilterTriggersAnAbort) {
  auto [status, std_out, std_err] = Run("MySuite.BadFilter");
  EXPECT_THAT(std_err, HasSubstr("Ineffective use of Filter()"));
  EXPECT_THAT(std_err, Not(HasSubstr("argument 0:")));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, BadWithMinSizeTriggersAnAbort) {
  auto [status, std_out, std_err] = Run("MySuite.BadWithMinSize");
  EXPECT_THAT(std_err, HasSubstr("Ineffective use of WithSize()"));
  EXPECT_THAT(std_err, Not(HasSubstr("argument 0:")));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, SmartPointer) {
  auto [status, std_out, std_err] = Run("MySuite.SmartPointer");
  EXPECT_THAT(std_err, HasSubstr("argument 0: (1"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, UnprintableTypeRunsAndPrintsSomething) {
  auto [status, std_out, std_err] = Run("MySuite.UsesUnprintableType");
  EXPECT_THAT(std_err, HasSubstr("argument 0: <unprintable value>"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, MyStructTestArbitraryCanPrint) {
  auto [status, std_out, std_err] = Run("MySuite.MyStructArbitrary");
  EXPECT_THAT(std_err, HasSubstr("argument 0: {0, \"X"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, MyStructTestWithDomainsCanPrint) {
  auto [status, std_out, std_err] = Run("MySuite.MyStructWithDomains");
  EXPECT_THAT(std_err, HasSubstr("argument 0: {0, \"X"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, ConstructorPrintsSomething) {
  auto [status, std_out, std_err] = Run("MySuite.ConstructorWithDomains");
  EXPECT_THAT(std_err, HasSubstr("\"ccc\""));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, SeedInputIsUsed) {
  auto [status, std_out, std_err] = Run("MySuite.SeedInputIsUsed");
  EXPECT_THAT(std_err, HasSubstr("argument 0: {9439518, 21, 49153}"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest,
       SeedInputIsUsedInProtobufsWithInternalMappings) {
  auto [status, std_out, std_err] =
      Run("MySuite.SeedInputIsUsedInProtobufsWithInternalMappings");
  EXPECT_THAT(std_err, HasSubstr("subproto_i32: 9439518"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, SeedInputIsUsedForMutation) {
  auto [status, std_out, std_err] = Run("MySuite.SeedInputIsUsedForMutation");
  EXPECT_THAT(std_err, HasSubstr("argument 0: {1979, 19, 1234, 5678}"));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, UsesManualDictionary) {
  auto [status, std_out, std_err] = Run("MySuite.StringPermutationTest");
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"9876543210\""));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, UsesSeededDomain) {
  auto [status, std_out, std_err] = Run("MySuite.StringPermutationWithSeeds");
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"9876543210\""));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, UsesSeedFromSeedProvider) {
  auto [status, std_out, std_err] =
      Run("MySuite.StringPermutationWithSeedProvider");
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"9876543210\""));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, UsesSeedFromSeedProviderOnFixture) {
  auto [status, std_out, std_err] =
      Run("SeededFixture.StringPermutationWithSeedProvider");
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"9876543210\""));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest,
       FunctionPointerAliasFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] =
      Run("MySuite.FunctionPointerAliasesAreFuzzable");
  EXPECT_THAT(std_err, HasSubstr("argument 0: "));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest,
       FunctionReferenceAliasFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] =
      Run("MySuite.FunctionReferenceAliasesAreFuzzable");
  EXPECT_THAT(std_err, HasSubstr("argument 0: "));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest, FuzzTestCanFindStackOverflows) {
  // TODO(b/302012926): Consolidate the stack overflow checking between FuzzTest
  // and Centipede.
#ifdef FUZZTEST_USE_CENTIPEDE
  GTEST_SKIP()
      << "Skipping the stack calculation tests when running with Centipede. "
         "Please run with --config=fuzztest to enable these tests!";
#endif
  auto [status, std_out, std_err] = Run("MySuite.DataDependentStackOverflow");
  EXPECT_THAT(std_err, HasSubstr("argument 0: "));
  EXPECT_THAT(
      std_err,
      ContainsRegex("Code under test used [0-9]* bytes of stack. Configured "
                    "limit is 131072. You can change the limit by specifying "
                    "FUZZTEST_STACK_LIMIT environment variable."));
  ExpectTargetAbort(status, std_err);
}

TEST_F(FuzzingModeCrashFindingTest,
       StackCalculationWorksWithAlternateStackForSignalHandlers) {
  // TODO(b/302012926): Consolidate the stack overflow checking between FuzzTest
  // and Centipede.
#ifdef FUZZTEST_USE_CENTIPEDE
  GTEST_SKIP()
      << "Skipping the stack calculation tests when running with Centipede. "
         "Please run with --config=fuzztest to enable these tests!";
#endif
  auto [status, std_out, std_err] =
      Run("MySuite.StackCalculationWorksWithAlternateStackForSignalHandlers");
  EXPECT_THAT(std_err, HasSubstr("argument 0: 123456789"));
  EXPECT_THAT(
      std_err,
      Not(HasSubstr(
          "You can change the limit by specifying FUZZTEST_STACK_LIMIT")));
  ExpectTargetAbort(status, std_err);
}

}  // namespace
}  // namespace fuzztest::internal
