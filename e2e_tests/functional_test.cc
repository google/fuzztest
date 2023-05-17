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

std::string GetGTestFilterFlag(std::string_view flag_value) {
  return absl::StrCat("--", GTEST_FLAG_PREFIX_, "filter=", flag_value);
}

std::string BinaryPath(const absl::string_view name =
                           "testdata/fuzz_tests_for_functional_testing") {
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

RunResults RunBinaryWith(
    std::string_view binary, std::string_view flags,
    const absl::flat_hash_map<std::string, std::string>& env = {},
    absl::Duration timeout = absl::InfiniteDuration()) {
  // We need to unset these env vars to prevent the testing infrastructure from
  // getting false positives from the child processes failures. See:
  // https://docs.bazel.build/versions/master/test-encyclopedia.html#initial-conditions
  unsetenv("TEST_PREMATURE_EXIT_FILE");
  unsetenv("TEST_WARNINGS_OUTPUT_FILE");

  // Reset shard environment variables to ensure subprocesses don't limit
  // themselves to our shards.
  // These are set by the testing environment to run us (ie functional_test.cc)
  // in sharded mode, but we don't want to run our child process in sharding
  // mode when using --gunit_filter. If we do, the test we are looking for might
  // be in a different shard that the one specified by TEST_SHARD_INDEX.
  unsetenv("TEST_TOTAL_SHARDS");
  unsetenv("TEST_SHARD_INDEX");

  std::vector<std::string> args = {std::string(binary)};
  std::vector<std::string> split_flags = absl::StrSplit(flags, ' ');
  args.insert(args.end(), split_flags.begin(), split_flags.end());

  return RunCommand(args, env, timeout);
}

RunResults RunWith(
    std::string_view flags,
    const absl::flat_hash_map<std::string, std::string>& env = {},
    absl::Duration timeout = absl::InfiniteDuration()) {
  return RunBinaryWith(BinaryPath(), flags, env, timeout);
}

// The following tests are on "unit testing mode" functionality, and can run
// both with and without coverage instrumentation.

TEST(UnitTestModeTest, FuzzTestsAreFoundInTheBinary) {
  auto [status, std_out, std_err] = RunWith("--list_fuzz_tests");
  EXPECT_THAT(std_out, HasSubstr("[*] Fuzz test: MySuite.Coverage"));
  EXPECT_THAT(std_out, HasSubstr("[*] Fuzz test: MySuite.DivByZero"));
  EXPECT_THAT(std_out,
              HasSubstr("[*] Fuzz test: MySuite.PassesWithPositiveInput"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, WrongFuzzTestNameTriggersError) {
  auto [status, std_out, std_err] = RunWith("--fuzz=WrongName");
  EXPECT_THAT(std_err, HasSubstr("No FUZZ_TEST matches the name: WrongName"));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST(UnitTestModeTest, MatchingMultipleFuzzTestsTriggersError) {
  auto [status, std_out, std_err] = RunWith("--fuzz=Bad");
  EXPECT_THAT(
      std_err,
      HasSubstr(
          "Multiple FUZZ_TESTs match the name: Bad\n\nPlease select one. "
          "Matching tests:\n MySuite.BadFilter\n MySuite.BadWithMinSize\n"));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST(UnitTestModeTest, PassingTestPassesInUnitTestingMode) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.PassesWithPositiveInput"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, InvalidSeedsCauseErrorMessageAndExit) {
  auto [status, std_out, std_err] =
      RunBinaryWith(BinaryPath("testdata/fuzz_tests_with_invalid_seeds"), "");
  EXPECT_THAT(std_err, HasSubstr("[!] Error using `WithSeeds()` in"));
  EXPECT_THAT(std_err, HasSubstr("Invalid seed value:\n\n{17}\n"));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST(UnitTestModeTest, CorpusIsMutatedInUnitTestMode) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.PassesString"));
  EXPECT_THAT(std_err, HasSubstr("==<<Saw size=0>>=="));
  EXPECT_THAT(std_err, HasSubstr("==<<Saw size=1>>=="));
  EXPECT_THAT(std_err, HasSubstr("==<<Saw size=2>>=="));
  EXPECT_THAT(std_err, HasSubstr("==<<Saw size=3>>=="));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, UnitTestModeLimitsNumberOfIterationsByWallTime) {
  // We run this in unittest mode to check that we reduce the number of
  // iterations to accommodate for the longer run time.
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.OneIterationTakesTooMuchTime"));
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
      absl::Substitute(R"re(TEST\($0, $1.*\) {\n.*$1\(\n.*$2.*\n.*\).*\n})re",
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
    bool asan_handles_abort) {
  auto [status, std_out, std_err] =
      asan_handles_abort
          ? RunWith(GetGTestFilterFlag(
                        "MySuite.GoogleTestExpect:MySuite.GoogleTestAssert"),
                    {{"ASAN_OPTIONS", "handle_abort=2"}})
          : RunWith(GetGTestFilterFlag(
                "MySuite.GoogleTestExpect:MySuite.GoogleTestAssert"));

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

TEST(UnitTestModeTest, GoogleTestExpectationsDontAbortInUnitTestMode) {
  GoogleTestExpectationsDontAbortInUnitTestModeImpl(false);
}

TEST(UnitTestModeTest,
     GoogleTestExpectationsDontAbortInUnitTestModeWhenAsanHandlesAbort) {
  GoogleTestExpectationsDontAbortInUnitTestModeImpl(true);
}

TEST(UnitTestModeTest, GlobalEnvironmentGoesThroughCompleteLifecycle) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.GoogleTestExpect"));
  EXPECT_EQ(
      1, CountSubstrs(std_err, "<<GlobalEnvironment::GlobalEnvironment()>>"));
  EXPECT_EQ(1, CountSubstrs(std_err, "<<GlobalEnvironment::SetUp()>>"));
  EXPECT_EQ(1, CountSubstrs(std_err, "<<GlobalEnvironment::TearDown()>>"));
  EXPECT_EQ(
      1, CountSubstrs(std_err, "<<GlobalEnvironment::~GlobalEnvironment()>>"));
}

TEST(UnitTestModeTest, FixtureGoesThroughCompleteLifecycle) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("FixtureTest.NeverFails"));
  EXPECT_EQ(1, CountSubstrs(std_err, "<<FixtureTest::FixtureTest()>>"));
  EXPECT_EQ(1, CountSubstrs(std_err, "<<FixtureTest::~FixtureTest()>>"));
}

TEST(UnitTestModeTest,
     GoogleTestPerIterationFixtureInstantiatedOncePerIteration) {
  auto [status, std_out, std_err] = RunWith(GetGTestFilterFlag(
      "CallCountPerIteration.CallCountIsAlwaysIncrementedFromInitialValue"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest,
     GoogleTestPerFuzzTestFixtureInstantiatedOncePerFuzzTest) {
  auto [status, std_out, std_err] = RunWith(
      GetGTestFilterFlag("CallCountPerFuzzTest.CallCountReachesAtLeastTen"));
  EXPECT_EQ(
      1, CountSubstrs(std_err, "<<CallCountGoogleTest::call_count_ == 10>>"));
}

TEST(UnitTestModeTest, GoogleTestStaticTestSuiteFunctionsCalledOnce) {
  auto [status, std_out, std_err] = RunWith(
      GetGTestFilterFlag("CallCountPerFuzzTest.CallCountReachesAtLeastTen:"
                         "CallCountPerFuzzTest.NeverFails"));
  EXPECT_EQ(1,
            CountSubstrs(std_err, "<<CallCountGoogleTest::SetUpTestSuite()>>"));
  EXPECT_EQ(
      1, CountSubstrs(std_err, "<<CallCountGoogleTest::TearDownTestSuite()>>"));
}

TEST(UnitTestModeTest, GoogleTestWorksWithProtoExtensionsUsedInSeeds) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.CheckProtoExtensions"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("Uses proto extensions"));
}

TEST(UnitTestModeTest, UnitTestAndFuzzTestCanShareSuiteName) {
  auto [status, std_out, std_err] = RunWith(GetGTestFilterFlag(
      "SharedSuite.WorksAsUnitTest:SharedSuite.WorksAsFuzzTest"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, RepeatedFieldsHaveMinSizeWhenInitialized) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.RepeatedFieldHasMinimumSize"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, OptionalProtoFieldCanHaveNoValue) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.FailsWhenFieldI32HasNoValue"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST(UnitTestModeTest, OptionalProtoFieldThatIsUnsetNeverHasValue) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.FailsWhenFieldI64HasValue"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, ProtoFieldsThatAreUnsetNeverHaveValue) {
  auto [status, std_out, std_err] = RunWith(
      GetGTestFilterFlag("MySuite.FailsWhen64IntegralFieldsHaveValues"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest,
     ProtoFieldThatAreCustomizedAndAlwaysSetHaveCorrectValue) {
  auto [status, std_out, std_err] = RunWith(
      GetGTestFilterFlag("MySuite.FailsWhenFieldsOfTypeDoubleHasNoValue"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, ProtoFieldsThatAreAlwaysSetAlwaysHaveValue) {
  auto [status, std_out, std_err] = RunWith(
      GetGTestFilterFlag("MySuite.FailsWhen64IntegralFieldsHaveNoValues"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, CanCustomizeProtoFieldsWithTransformers) {
  auto [status, std_out, std_err] = RunWith(GetGTestFilterFlag(
      "MySuite."
      "FailsIfRepeatedEnumsHaveZeroValueAndOptionalEnumHasNonZeroValue"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, RequiredProtoFieldWillBeSetWhenNullnessIsNotCustomized) {
  auto [status, std_out, std_err] = RunWith(
      GetGTestFilterFlag("MySuite.FailsWhenRequiredInt32FieldHasNoValue"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, RequiredProtoFieldThatIsNotAlwaysSetCanHaveNoValue) {
  auto [status, std_out, std_err] = RunWith(
      GetGTestFilterFlag("MySuite.FailsWhenRequiredEnumFieldHasNoValue"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("cannot have null values"));
}

TEST(UnitTestModeTest, OptionalProtoFieldThatIsNotAlwaysSetCanHaveNoValue) {
  auto [status, std_out, std_err] = RunWith(
      GetGTestFilterFlag("MySuite.FailsWhenOptionalFieldU32HasNoValue"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST(UnitTestModeTest, ProtobufOfMutatesTheProto) {
  auto [status, std_out, std_err] = RunWith(
      GetGTestFilterFlag("MySuite.FailsWhenI32ContainsTheSecretNumber"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("Secret number is found"));
}

TEST(UnitTestModeTest, ProtobufEnumEqualsLabel4) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.FailsIfProtobufEnumEqualsLabel4"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(
      std_err,
      HasSubstr("argument 0: fuzztest::internal::TestProtobuf::Label4"));
}

TEST(UnitTestModeTest, WorksWithRecursiveStructs) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.WorksWithRecursiveStructs"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  // Nullptr has multiple possible human-readable representations.
  EXPECT_THAT(std_err, AnyOf(HasSubstr("argument 0: {0, 1}"),
                             HasSubstr("argument 0: {(nil), 1}")));
}

TEST(UnitTestModeTest, WorksWithStructsWithConstructors) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.WorksWithStructsWithConstructors"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("argument 0: {1, \"abc\"}"));
}

TEST(UnitTestModeTest, WorksWithStructsWithEmptyTuples) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.WorksWithStructsWithEmptyTuples"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("argument 0: {}"));
}

TEST(UnitTestModeTest, WorksWithEmptyStructs) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.WorksWithEmptyStructs"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("argument 0: {}"));
}

TEST(UnitTestModeTest, WorksWithStructsWithEmptyFields) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.WorksWithStructsWithEmptyFields"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("argument 0: {{}}"));
}

TEST(UnitTestModeTest, WorksWithEmptyInheritance) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.WorksWithEmptyInheritance"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("argument 0: {0, \"abc\"}"));
}

TEST(UnitTestModeTest, ArbitraryWorksWithEmptyInheritance) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.ArbitraryWorksWithEmptyInheritance"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("argument 0:"));
}

TEST(UnitTestModeTest, FlatMapCorrectlyPrintsValues) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.FlatMapCorrectlyPrintsValues"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  // This is the argument to the output domain.
  EXPECT_THAT(std_err, HasSubstr("argument 0: {\"AAA\", \"BBB\"}"));
  // This is the argument to the input domain.
  EXPECT_THAT(std_err, Not(HasSubstr("argument 0: 3")));
}

TEST(UnitTestModeTest, PropertyFunctionAcceptsTupleOfItsSingleParameter) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.UnpacksTupleOfOne"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST(UnitTestModeTest, PropertyFunctionAcceptsTupleOfItsThreeParameters) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.UnpacksTupleOfThree"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST(UnitTestModeTest, PropertyFunctionAcceptsTupleContainingTuple) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.UnpacksTupleContainingTuple"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST(UnitTestModeTest, ProtoFieldsCanBeAlwaysSet) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.FailsWhenSubprotoIsNull"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, ProtoFieldsCanBeUnset) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.FailsWhenSubprotoFieldsAreSet"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, RepeatedProtoFieldsCanBeCustomized) {
  auto [status, std_out, std_err] = RunWith(GetGTestFilterFlag(
      "MySuite.FailsWhenRepeatedSubprotoIsSmallOrHasAnEmptyElement"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, DefaultOptionalPolicyAppliesToAllOptionalFields) {
  auto [status, std_out, std_err] = RunWith(
      GetGTestFilterFlag("MySuite.FailsWhenAnyOptionalFieldsHaveValue"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest,
     DefaultOptionalPolicyAppliesToAllOptionalFieldsWithoutOverwrittenDomain) {
  auto [status, std_out, std_err] = RunWith(GetGTestFilterFlag(
      "MySuite."
      "FailsWhenAnyOptionalFieldsHaveValueButNotFieldsWithOverwrittenDomain"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest,
     DefaultOptionalPolicyAppliesToAllOptionalFieldsWithoutOverwrittenPolicy) {
  auto [status, std_out, std_err] = RunWith(GetGTestFilterFlag(
      "MySuite."
      "FailsWhenAnyOptionalFieldsHaveValueButNotFieldsWithOverwrittenPolicy"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, DetectsRecursiveStructureIfOptionalsSetByDefault) {
  auto [status, std_out, std_err] =
      RunWith(GetGTestFilterFlag("MySuite.FailsIfCantInitializeProto"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("recursive fields"));
}

TEST(UnitTestModeTest,
     AvoidsFailureIfSetByDefaultPolicyIsOverwrittenOnRecursiveStructures) {
  auto [status, std_out, std_err] = RunWith(GetGTestFilterFlag(
      "MySuite."
      "InitializesRecursiveProtoIfInfiniteRecursivePolicyIsOverwritten"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, DefaultRepeatedFieldsMinSizeAppliesToAllRepeatedFields) {
  auto [status, std_out, std_err] = RunWith(GetGTestFilterFlag(
      "MySuite.FailsIfRepeatedFieldsDontHaveTheMinimumSize"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, DefaultRepeatedFieldsMaxSizeAppliesToAllRepeatedFields) {
  auto [status, std_out, std_err] = RunWith(GetGTestFilterFlag(
      "MySuite.FailsIfRepeatedFieldsDontHaveTheMaximumSize"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, UsesPolicyProvidedDefaultDomainForProtos) {
  auto [status, std_out, std_err] = RunWith(
      GetGTestFilterFlag("MySuite.FailsWhenSubprotosDontSetOptionalI32"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, ChecksTypeOfProvidedDefaultDomainForProtos) {
  auto [status, std_out, std_err] = RunWith(GetGTestFilterFlag(
      "MySuite.FailsWhenWrongDefaultProtobufDomainIsProvided"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
  EXPECT_THAT(std_err, HasSubstr("does not match the expected message type"));
}

TEST(UnitTestModeTest, PoliciesApplyToFieldsInOrder) {
  auto [status, std_out, std_err] = RunWith(GetGTestFilterFlag(
      "MySuite.FailsWhenI32FieldValuesDontRespectAllPolicies"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST(UnitTestModeTest, AlwaysSetAndUnsetWorkOnOneofFields) {
  auto [status, std_out, std_err] = RunWith(
      GetGTestFilterFlag("MySuite.FailsWhenOneofFieldDoesntHaveOneofValue"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

// The following tests are on "fuzzing mode" functionality, and can only run
// with coverage instrumentation enabled.
class FuzzingModeTest : public ::testing::Test {
 protected:
  void SetUp() override {
#if defined(__has_feature)
#if !__has_feature(coverage_sanitizer)
    GTEST_SKIP() << "No coverage instrumentation: skipping fuzzing mode test. "
                    "Please run with --config=fuzztest to enable these tests!";
#endif
#endif
  }
};

TEST_F(FuzzingModeTest, AbortTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.Aborts");
  EXPECT_THAT(std_err, HasSubstr("argument 0: "));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, FuzzTestCanBeSelectedForFuzzingUsingSubstring) {
  auto [status, std_out, std_err] = RunWith("--fuzz=Abort");
  EXPECT_THAT(std_err, HasSubstr("argument 0: "));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, BufferOverflowIsDetectedWithStringViewInFuzzingMode) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.BufferOverreadWithStringView");
  EXPECT_THAT(
      std_err,
      AnyOf(HasSubstr("ERROR: AddressSanitizer: container-overflow"),
            HasSubstr("ERROR: AddressSanitizer: heap-buffer-overflow")));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST_F(FuzzingModeTest,
       DereferencingEmptyOptionalTriggersLibcppAssertionsWhenEnabled) {
#if defined(_LIBCPP_VERSION) && defined(_LIBCPP_ENABLE_ASSERTIONS)
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.DereferenceEmptyOptional");
  EXPECT_THAT(std_err, HasSubstr("argument 0: std::nullopt"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
#endif
}

TEST_F(FuzzingModeTest, BufferOverflowIsDetectedWithStringInFuzzingMode) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.BufferOverreadWithString");
  EXPECT_THAT(std_err,
              HasSubstr("ERROR: AddressSanitizer: heap-buffer-overflow"));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST_F(FuzzingModeTest,
       BufferOverflowIsDetectedWithStringAndLvalueStringViewRef) {
  auto [status, std_out, std_err] = RunWith(
      "--fuzz=MySuite.BufferOverreadWithStringAndLvalueStringViewRef");
  EXPECT_THAT(std_err,
              HasSubstr("ERROR: AddressSanitizer: heap-buffer-overflow"));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST_F(FuzzingModeTest,
       BufferOverflowIsDetectedWithStringAndRvalueStringViewRef) {
  auto [status, std_out, std_err] = RunWith(
      "--fuzz=MySuite.BufferOverreadWithStringAndRvalueStringViewRef");
  EXPECT_THAT(std_err,
              HasSubstr("ERROR: AddressSanitizer: heap-buffer-overflow"));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST_F(FuzzingModeTest, DivByZeroTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.DivByZero");
  EXPECT_THAT(std_err, HasSubstr("argument 1: 0"));
#ifdef ADDRESS_SANITIZER
  EXPECT_THAT(status, Ne(ExitCode(0)));
#else
  EXPECT_THAT(status, Eq(Signal(SIGFPE)));
#endif
}

TEST_F(FuzzingModeTest, CoverageTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.Coverage");
  EXPECT_THAT(std_err, HasSubstr("argument 0: 'F'"));
  EXPECT_THAT(std_err, HasSubstr("argument 1: 'u'"));
  EXPECT_THAT(std_err, HasSubstr("argument 2: 'z'"));
  EXPECT_THAT(std_err, HasSubstr("argument 3: 'z'"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, StringTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.String");
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"Fuzz"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, StringAsciiOnlyTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.StringAsciiOnly");
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"Fuzz"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, StringRegexpTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.StringRegexp");
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"Fuzz"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, StringViewTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.StringView");
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"Fuzz"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, StrCmpTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.StrCmp");
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"Hello!"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, BitFlagsFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.BitFlags");
  EXPECT_THAT(std_err, HasSubstr("argument 0: 21"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, EnumTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.EnumValue");
  EXPECT_THAT(std_err, HasSubstr("argument 0: Color{0}"));
  EXPECT_THAT(std_err, HasSubstr("argument 1: Color{1}"));
  EXPECT_THAT(std_err, HasSubstr("argument 2: Color{2}"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, EnumClassTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.EnumClassValue");
  EXPECT_THAT(std_err, HasSubstr("argument 0: ColorClass{0}"));
  EXPECT_THAT(std_err, HasSubstr("argument 1: ColorClass{1}"));
  EXPECT_THAT(std_err, HasSubstr("argument 2: ColorClass{2}"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, ProtoTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.Proto");
  EXPECT_THAT(std_err, ContainsRegex(R"(argument 0: \(b:\s+true)"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, BitvectorValueTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.BitvectorValue");
  EXPECT_THAT(std_err, HasSubstr("argument 0: {true"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, VectorValueTestFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.VectorValue");
  EXPECT_THAT(std_err, HasSubstr("argument 0: {'F'"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, GoogleTestExpectationsStopTheFuzzer) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.GoogleTestExpect");
  EXPECT_THAT(std_err, HasSubstr("argument 0: "));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));

  // There is the repro example only on stderr.
  EXPECT_THAT(std_out,
              Not(HasReproducerTest("MySuite", "GoogleTestExpect", ".*")));
  EXPECT_THAT(std_err, HasReproducerTest("MySuite", "GoogleTestExpect", ".*"));
}

TEST_F(FuzzingModeTest, GoogleTestAssertionsStopTheFuzzer) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.GoogleTestAssert");
  EXPECT_THAT(std_err, HasSubstr("argument 0: "));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));

  // There is the repro example only on stderr.
  EXPECT_THAT(std_out,
              Not(HasReproducerTest("MySuite", "GoogleTestAssert", ".*")));
  EXPECT_THAT(std_err, HasReproducerTest("MySuite", "GoogleTestAssert", ".*"));
}

TEST_F(FuzzingModeTest, IgnoresNegativeFuzzingRunsLimitInEnvVar) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.PassesWithPositiveInput",
              {{"FUZZTEST_MAX_FUZZING_RUNS", "-1"}},
              /*timeout=*/absl::Seconds(1));
  EXPECT_THAT(std_err, HasSubstr("will not limit fuzzing runs")) << std_err;
}

TEST_F(FuzzingModeTest, LimitsFuzzingRunsWhenEnvVarIsSet) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.PassesWithPositiveInput",
              {{"FUZZTEST_MAX_FUZZING_RUNS", "100"}});
  EXPECT_THAT(std_err,
              // 100 fuzzing runs + 1 seed run.
              HasSubstr("Total runs: 101"))
      << std_err;
}

TEST_F(FuzzingModeTest, LimitsFuzzingRunsWhenTimeoutIsSet) {
  auto [status, std_out, std_err] = RunWith(
      "--fuzz=MySuite.PassesWithPositiveInput --fuzz_for=1s");
  EXPECT_THAT(std_err, HasSubstr("Fuzzing timeout set to: 1s")) << std_err;
}

TEST_F(FuzzingModeTest, ReproducerIsDumpedWhenEnvVarIsSet) {
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

TEST_F(FuzzingModeTest, SavesCorpusWhenEnvVarIsSet) {
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

TEST_F(FuzzingModeTest, RestoresCorpusWhenEnvVarIsSet) {
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

TEST_F(FuzzingModeTest, MinimizesCorpusWhenEnvVarIsSet) {
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

TEST_F(FuzzingModeTest, MinimizesDuplicatedCorpus) {
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

TEST_F(FuzzingModeTest, ReplayingNonCrashingReproducerDoesNotCrash) {
  ReplayFile replay(std::in_place, std::tuple<std::string>{"NotFuzz"});

  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.String", replay.GetReplayEnv());
  EXPECT_THAT(status, Eq(ExitCode(0))) << std_err;
}

TEST_F(FuzzingModeTest, ReplayingCrashingReproducerCrashes) {
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
TEST_F(FuzzingModeTest, ReproducerIsDumpedWhenEnvVarIsSetTypeErased) {
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

TEST_F(FuzzingModeTest, ReplayingNonCrashingReproducerDoesNotCrashTypeErased) {
  ReplayFile replay(std::in_place, std::tuple<uint8_t, double>{11, 11});

  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.WithDomainClass", replay.GetReplayEnv());
  EXPECT_THAT(status, Eq(ExitCode(0))) << std_err;
}

TEST_F(FuzzingModeTest, ReplayingCrashingReproducerCrashesTypeErased) {
  ReplayFile replay(std::in_place, std::tuple<uint8_t, double>{10, 1979.125});
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.WithDomainClass", replay.GetReplayEnv());
  EXPECT_THAT(std_err, HasSubstr("argument 0: 10"));
  EXPECT_THAT(std_err, HasSubstr("argument 1: 1979.125"));
  EXPECT_THAT(status, Ne(ExitCode(0)));
}

TEST_F(FuzzingModeTest, MappedDomainShowsMappedValue) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.Mapping");
  EXPECT_THAT(
      std_err,
      AllOf(
          HasSubstr("argument 0: \"12 monkeys\""),
          HasReproducerTest(
              "MySuite", "Mapping",
              // Account for the possibility that the symbol
              // NumberOfAnimalsToString may be mangled.
              R"re(.*NumberOfAnimalsToString.*\(TimesTwo\(6\), "monkey"\))re")));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, FlatMappedDomainShowsMappedValue) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.FlatMapping");
  EXPECT_THAT(std_err, AllOf(HasSubstr("argument 0: {\"abc\", 2}"),
                             HasReproducerTest(
                                 "MySuite", "FlatMapping",
                                 // Account for the possibility that the symbol
                                 // StringAndValidIndex may be mangled.
                                 R"re(.*StringAndValidIndex.*\("abc"\))re")));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, FlatMapPassesWhenCorrect) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.FlatMapPassesWhenCorrect", /*env=*/{},
              /*timeout=*/absl::Seconds(1));
  EXPECT_THAT(std_err, HasSubstr("Fuzzing was terminated"));
  EXPECT_THAT(std_err, HasSubstr("=== Fuzzing stats"));
  EXPECT_THAT(std_err, HasSubstr("Total runs:"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(FuzzingModeTest, FilterDomainShowsOnlyFilteredValues) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.Filtering");
  EXPECT_THAT(std_err, HasSubstr("argument 0: 8"));
  EXPECT_THAT(std_err, HasSubstr("argument 1: 9"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, BadFilterTriggersAnAbort) {
  auto [status, std_out, std_err] = RunWith("--fuzz=MySuite.BadFilter");
  EXPECT_THAT(std_err, HasSubstr("Ineffective use of Filter()"));
  EXPECT_THAT(std_err, Not(HasSubstr("argument 0:")));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, BadWithMinSizeTriggersAnAbort) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.BadWithMinSize");
  EXPECT_THAT(std_err, HasSubstr("Ineffective use of WithSize()"));
  EXPECT_THAT(std_err, Not(HasSubstr("argument 0:")));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, SmartPointer) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.SmartPointer");
  EXPECT_THAT(std_err, HasSubstr("argument 0: (1"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, UnprintableTypeRunsAndPrintsSomething) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.UsesUnprintableType");
  EXPECT_THAT(std_err, HasSubstr("argument 0: <unprintable value>"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, MinimizerFindsSmallerInput) {
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

TEST_F(FuzzingModeTest, MyStructTestArbitraryCanPrint) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.MyStructArbitrary");
  EXPECT_THAT(std_err, HasSubstr("argument 0: {0, \"X"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, MyStructTestWithDomainsCanPrint) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.MyStructWithDomains");
  EXPECT_THAT(std_err, HasSubstr("argument 0: {0, \"X"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, ConstructorPrintsSomething) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.ConstructorWithDomains");
  EXPECT_THAT(std_err, HasSubstr("\"ccc\""));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, FuzzerStatsArePrintedOnTermination) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.PassesWithPositiveInput", /*env=*/{},
              /*timeout=*/absl::Seconds(1));
  EXPECT_THAT(std_err, HasSubstr("Fuzzing was terminated"));
  EXPECT_THAT(std_err, HasSubstr("=== Fuzzing stats"));
  EXPECT_THAT(std_err, HasSubstr("Total runs:"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(FuzzingModeTest, SeedInputIsUsed) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.SeedInputIsUsed");
  EXPECT_THAT(std_err, HasSubstr("argument 0: {9439518, 21, 49153}"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, SeedInputIsUsedInProtobufsWithInternalMappings) {
  auto [status, std_out, std_err] = RunWith(
      "--fuzz=MySuite.SeedInputIsUsedInProtobufsWithInternalMappings");
  EXPECT_THAT(std_err, HasSubstr("subproto_i32: 9439518"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, SeedInputIsUsedForMutation) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.SeedInputIsUsedForMutation");
  EXPECT_THAT(std_err, HasSubstr("argument 0: {1979, 19, 1234, 5678}"));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, UsesManualDictionary) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.StringPermutationTest",
              /*env=*/{}, /*timeout=*/absl::Seconds(10));
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"9876543210\""));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, UsesSeededDomain) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.StringPermutationWithSeeds",
              /*env=*/{}, /*timeout=*/absl::Seconds(10));
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"9876543210\""));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, UsesSeedFromSeedProvider) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.StringPermutationWithSeedProvider",
              /*env=*/{}, /*timeout=*/absl::Seconds(10));
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"9876543210\""));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, UsesSeedFromSeedProviderOnFixture) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=SeededFixture.StringPermutationWithSeedProvider",
              /*env=*/{}, /*timeout=*/absl::Seconds(10));
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"9876543210\""));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, FunctionPointerAliasFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.FunctionPointerAliasesAreFuzzable");
  EXPECT_THAT(std_err, HasSubstr("argument 0: "));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, FunctionReferenceAliasFindsAbortInFuzzingMode) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.FunctionReferenceAliasesAreFuzzable");
  EXPECT_THAT(std_err, HasSubstr("argument 0: "));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, GlobalEnvironmentIsSetUpForFailingTest) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.GoogleTestExpect");
  EXPECT_EQ(
      1, CountSubstrs(std_err, "<<GlobalEnvironment::GlobalEnvironment()>>"));
  EXPECT_EQ(1, CountSubstrs(std_err, "<<GlobalEnvironment::SetUp()>>"));
}

TEST_F(FuzzingModeTest,
       GlobalEnvironmentGoesThroughCompleteLifecycleForSuccessfulTest) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.GoogleTestNeverFails", /*env=*/{},
              /*timeout=*/absl::Seconds(1));
  EXPECT_EQ(
      1, CountSubstrs(std_err, "<<GlobalEnvironment::GlobalEnvironment()>>"));
  EXPECT_EQ(1, CountSubstrs(std_err, "<<GlobalEnvironment::SetUp()>>"));
  EXPECT_EQ(1, CountSubstrs(std_err, "<<GlobalEnvironment::TearDown()>>"));
  EXPECT_EQ(
      1, CountSubstrs(std_err, "<<GlobalEnvironment::~GlobalEnvironment()>>"));
}

TEST_F(FuzzingModeTest, GoogleTestHasCurrentTestInfo) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.GoogleTestHasCurrentTestInfo", /*env=*/{},
              /*timeout=*/absl::Seconds(1));
  EXPECT_THAT(std_out,
              HasSubstr("[       OK ] MySuite.GoogleTestHasCurrentTestInfo"));
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(FuzzingModeTest, SilenceTargetWorking) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.TargetPrintSomethingThenAbrt",
              /*env=*/{{"FUZZTEST_SILENCE_TARGET", "1"}});
  EXPECT_THAT(std_out, Not(HasSubstr("Hello World from target stdout")));
  EXPECT_THAT(std_err, HasSubstr("=== Fuzzing stats"));
  EXPECT_THAT(std_err, Not(HasSubstr("Hello World from target stderr")));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, FixtureGoesThroughCompleteLifecycle) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=FixtureTest.NeverFails",
              {{"FUZZTEST_MAX_FUZZING_RUNS", "10"}});
  EXPECT_EQ(1, CountSubstrs(std_err, "<<FixtureTest::FixtureTest()>>"));
  EXPECT_EQ(1, CountSubstrs(std_err, "<<FixtureTest::~FixtureTest()>>"));
}

TEST_F(FuzzingModeTest,
       GoogleTestPerIterationFixtureInstantiatedOncePerIteration) {
  auto [status, std_out, std_err] = RunWith(
      "--fuzz=CallCountPerIteration."
      "CallCountIsAlwaysIncrementedFromInitialValue",
      {{"FUZZTEST_MAX_FUZZING_RUNS", "10"}});
  EXPECT_THAT(status, Eq(ExitCode(0)));
}

TEST_F(FuzzingModeTest,
       GoogleTestPerFuzzTestFixtureInstantiatedOncePerFuzzTest) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=CallCountPerFuzzTest.CallCountReachesAtLeastTen",
              {{"FUZZTEST_MAX_FUZZING_RUNS", "10"}});
  EXPECT_EQ(
      1, CountSubstrs(std_err, "<<CallCountGoogleTest::call_count_ == 10>>"));
}

TEST_F(FuzzingModeTest, GoogleTestStaticTestSuiteFunctionsCalledOnce) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=CallCountPerFuzzTest.CallCountReachesAtLeastTen",
              {{"FUZZTEST_MAX_FUZZING_RUNS", "10"}});
  EXPECT_EQ(1,
            CountSubstrs(std_err, "<<CallCountGoogleTest::SetUpTestSuite()>>"));
  EXPECT_EQ(
      1, CountSubstrs(std_err, "<<CallCountGoogleTest::TearDownTestSuite()>>"));
}

TEST_F(FuzzingModeTest, NonFatalFailureAllowsMinimization) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=MySuite.NonFatalFailureAllowsMinimization");
  // The final failure should be with the known minimal result, even though many
  // "larger" inputs also trigger the failure.
  EXPECT_THAT(std_err, HasSubstr("argument 0: \"0123\""));

  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest, FuzzTestCanFindStackOverflows) {
  auto [status, std_out, std_err] =
      RunWith("--fuzz=DataDependentStackOverflow");
  EXPECT_THAT(std_err, HasSubstr("argument 0: "));
  EXPECT_THAT(
      std_err,
      ContainsRegex("Code under test used [0-9]* bytes of stack. Configured "
                    "limit is 131072. You can change the limit by specifying "
                    "FUZZTEST_STACK_LIMIT environment variable."));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

TEST_F(FuzzingModeTest,
       StackCalculationWorksWithAlternateStackForSignalHandlers) {
  auto [status, std_out, std_err] = RunWith(
      "--fuzz=StackCalculationWorksWithAlternateStackForSignalHandlers");
  EXPECT_THAT(std_err, HasSubstr("argument 0: 123456789"));
  EXPECT_THAT(
      std_err,
      Not(HasSubstr(
          "You can change the limit by specifying FUZZTEST_STACK_LIMIT")));
  EXPECT_THAT(status, Eq(Signal(SIGABRT)));
}

}  // namespace
}  // namespace fuzztest::internal
