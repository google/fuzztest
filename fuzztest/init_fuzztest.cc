#include "./fuzztest/init_fuzztest.h"

#if defined(__linux__)
#include <unistd.h>
#endif

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "gtest/gtest.h"
#include "absl/algorithm/container.h"
#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_set.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/reflection.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "absl/time/time.h"
#include "./fuzztest/internal/configuration.h"
#include "./fuzztest/internal/flag_name.h"
#include "./fuzztest/internal/googletest_adaptor.h"
#include "./fuzztest/internal/io.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/registry.h"
#include "./fuzztest/internal/runtime.h"

#define FUZZTEST_DEFINE_FLAG(type, name, default_value, description) \
  ABSL_FLAG(type, FUZZTEST_FLAG_NAME(name), default_value, description)

FUZZTEST_DEFINE_FLAG(
    bool, list_fuzz_tests, false,
    "Prints (to stdout) the list of all available FUZZ_TEST-s in the "
    "binary and exits. I.e., prints the test names that can be run with "
    "the flag `--" FUZZTEST_FLAG_PREFIX "fuzz=<test name>`.")
    .OnUpdate([]() {
      fuzztest::internal::SetFuzzTestListingModeValidatorForGoogleTest(
          absl::GetFlag(FUZZTEST_FLAG(list_fuzz_tests)));
    });

static constexpr absl::string_view kUnspecified = "<unspecified>";

FUZZTEST_DEFINE_FLAG(
    std::string, fuzz, std::string(kUnspecified),
    "Runs a single FUZZ_TEST in continuous fuzzing mode. "
    "E.g., `--" FUZZTEST_FLAG_PREFIX
    "fuzz=MySuite.MyFuzzTest` runs the given FUZZ_TEST in "
    "fuzzing mode. You can also provide just a part of the name, e.g., "
    "`--" FUZZTEST_FLAG_PREFIX
    "fuzz=MyFuzz`, if it matches only a single FUZZ_TEST. "
    "If you have only one fuzz test in your binary, you can also use "
    "`--" FUZZTEST_FLAG_PREFIX
    "fuzz=` to run it in fuzzing mode (i.e., by setting the "
    "flag to empty string). "
    "In fuzzing mode the selected test runs until a bug is found or "
    "until manually stopped. Fuzzing mode uses coverage feedback to "
    "iteratively build up a corpus of inputs that maximize coverage and "
    "to reach deep bugs. Note that the binary must be compiled with "
    "`--config=fuzztest` for this to work, as it needs coverage "
    "instrumentation.");

FUZZTEST_DEFINE_FLAG(
    absl::Duration, fuzz_for, absl::InfiniteDuration(),
    "Runs all fuzz tests in fuzzing mode for the specified duration. Can "
    "be combined with --" FUZZTEST_FLAG_PREFIX
    "fuzz to select a single fuzz tests, or with --" GTEST_FLAG_PREFIX_
    "filter to select a subset of fuzz tests. Recommended to use with test "
    "sharding.");

FUZZTEST_DEFINE_FLAG(
    std::string, corpus_database,
    "~/.cache/fuzztest",
    "The directory containing all corpora for all fuzz tests in the project. "
    "For each test binary, there's a corresponding <binary_name> "
    "subdirectory in `corpus_database`, and  the <binary_name> directory has "
    "the following structure: (1) For each fuzz test `SuiteName.TestName` in "
    "the binary, there's a sub-directory with the name of that test "
    "('<binary_name>/SuiteName.TestName'). (2) For each fuzz test, there are "
    "three directories containing `regression`, `crashing`, and `coverage` "
    "directories. Files in the `regression` directory will always be used. "
    "Files in `crashing` directory will be used when "
    "--reproduce_findings_as_separate_tests flag is true. And finally, all "
    "files in `coverage` directory will be used when --replay_corpus flag is "
    "true.");

FUZZTEST_DEFINE_FLAG(bool, reproduce_findings_as_separate_tests, false,
                     "When true, the selected tests replay all crashing inputs "
                     "in the database as separate TEST-s.");

FUZZTEST_DEFINE_FLAG(
    bool, replay_coverage_inputs, false,
    "When true, the selected tests replay coverage inputs in the database for "
    "a given test. This is useful for measuring the coverage of the corpus "
    "built up during previously ran fuzzing sessions.");

FUZZTEST_DEFINE_FLAG(
    size_t, stack_limit_kb, 128,
    "The soft limit of the stack size in kibibytes to abort when "
    "the limit is exceeded. 0 indicates no limit.");

FUZZTEST_DEFINE_FLAG(size_t, rss_limit_mb, 0,
                     "The soft limit of the RSS size in mebibytes to abort "
                     "when the limit is exceeded. 0 indicates no limit.");

FUZZTEST_DEFINE_FLAG(
    absl::Duration, time_limit_per_input, absl::InfiniteDuration(),
    "The time limit of the property-function: A timeout bug will be reported "
    "for an input if the execution of the property-function with the input "
    "takes longer than this time limit.");

namespace fuzztest {

std::vector<std::string> ListRegisteredTests() {
  std::vector<std::string> result;
  internal::ForEachTest(
      [&](const auto& test) { result.push_back(test.full_name()); });
  return result;
}

std::string GetMatchingFuzzTestOrExit(std::string_view name) {
  const std::string partial_name(name);
  const std::vector<std::string> full_names = ListRegisteredTests();
  std::vector<const std::string*> matches;
  for (const std::string& full_name : full_names) {
    if (absl::StrContains(full_name, partial_name)) {
      if (full_name == partial_name) {
        // In case of an exact match, we end the search and use it. This is to
        // handle the case when we want to select `MySuite.MyTest`, but the
        // binary has both `MySuite.MyTest` and `MySuite.MyTestX`.
        return full_name;
      } else {
        matches.push_back(&full_name);
      }
    }
  }

  if (matches.empty()) {
    absl::FPrintF(stderr, "\n\nNo FUZZ_TEST matches the name: %s\n\n",
                  partial_name);
    absl::FPrintF(stderr, "Valid tests:\n");
    for (const std::string& full_name : full_names) {
      absl::FPrintF(stderr, " %s\n", full_name);
    }
    exit(1);
  } else if (matches.size() > 1) {
    absl::FPrintF(stderr, "\n\nMultiple FUZZ_TESTs match the name: %s\n\n",
                  partial_name);
    absl::FPrintF(stderr, "Please select one. Matching tests:\n");
    for (const std::string* full_name : matches) {
      absl::FPrintF(stderr, " %s\n", *full_name);
    }
    exit(1);
  }
  return *matches[0];
}

namespace {

internal::Configuration CreateConfigurationsFromFlags(
    absl::string_view binary_identifier) {
  bool reproduce_findings_as_separate_tests =
      absl::GetFlag(FUZZTEST_FLAG(reproduce_findings_as_separate_tests));
  absl::Duration time_limit_per_test = absl::GetFlag(FUZZTEST_FLAG(fuzz_for));
  if (time_limit_per_test <= absl::ZeroDuration()) {
    time_limit_per_test = absl::InfiniteDuration();
  }
  return internal::Configuration{
      absl::GetFlag(FUZZTEST_FLAG(corpus_database)),
      /*stats_root=*/"",
      std::string(binary_identifier),
      /*fuzz_tests=*/ListRegisteredTests(),
      reproduce_findings_as_separate_tests,
      absl::GetFlag(FUZZTEST_FLAG(replay_coverage_inputs)),
      /*stack_limit=*/absl::GetFlag(FUZZTEST_FLAG(stack_limit_kb)) * 1024,
      /*rss_limit=*/absl::GetFlag(FUZZTEST_FLAG(rss_limit_mb)) * 1024 * 1024,
      absl::GetFlag(FUZZTEST_FLAG(time_limit_per_input)), time_limit_per_test};
}

#if defined(__linux__)

std::string ShellEscape(absl::string_view str) {
  return absl::StrCat("'", absl::StrReplaceAll(str, {{"'", "'\\''"}}), "'");
}

void ExecvToCentipede(const char* centipede_binary, int argc, char** argv) {
  // Initialization code before `ExecvToCentipede` may establish a timer and a
  // signal handler, but only the timer persists through execve(). This can
  // cause program termination by unhandled signals and to avoid this, we unset
  // timer signals.
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_IGN;
  for (int timer_signo : {SIGALRM, SIGPROF, SIGVTALRM}) {
    if (sigaction(timer_signo, &sa, nullptr) < 0) {
      std::cerr << "Failed to ignore timer signal " << timer_signo
                << ". The program being launched may die if a profiling "
                   "timer expires before it can register its own handler.";
    }
  }
  std::string binary_arg = absl::StrCat("--binary=", argv[0]);
  // We need shell escaping, because parts of binary_arg will be passed to
  // system(), which uses the default shell.
  for (int i = 1; i < argc; ++i) {
    absl::StrAppend(&binary_arg, " ", ShellEscape(argv[i]));
  }
  // Additionally we need to append the parsed flags because Abseil removes
  // them from `argv`. We only append flags with a non-default value.
  for (const auto [flag_name, flag] : absl::GetAllFlags()) {
    if (flag->CurrentValue() == flag->DefaultValue()) continue;
    absl::StrAppend(
        &binary_arg, " ",
        ShellEscape(absl::StrCat("--", flag_name, "=", flag->CurrentValue())));
  }
  // `execv` guarantees it will not modify the passed arguments, so the
  // const_casts are OK.
  char* const args[] = {
      const_cast<char*>(centipede_binary),
      const_cast<char*>(binary_arg.c_str()),
      nullptr,
  };
  const int execv_ret = execv(centipede_binary, args);
  FUZZTEST_INTERNAL_CHECK(false, "execv() should never return. It returned ",
                          execv_ret, " with an error: ", std::strerror(errno));
}

#else

void ExecvToCentipede(const char*, int, char**) {
  FUZZTEST_INTERNAL_CHECK(
      false,
      "Switching to Centipede via FUZZTEST_CENTIPEDE_BINARY only works on "
      "Linux. Please run Centipede manually and use the --binary flag to pass "
      "the current binary.");
}

#endif  // defined(__linux__)
}  // namespace

void RunSpecifiedFuzzTest(std::string_view name, std::string_view binary_id) {
  const std::string matching_fuzz_test = GetMatchingFuzzTestOrExit(name);
  internal::Configuration configuration =
      CreateConfigurationsFromFlags({binary_id.data(), binary_id.size()});
  internal::ForEachTest([&](auto& test) {
    // TODO(b/301965259): Properly initialize the configuration.
    if (test.full_name() == matching_fuzz_test) {
      std::exit(test.make()->RunInFuzzingMode(/*argc=*/nullptr,
                                              /*argv=*/nullptr, configuration));
    }
  });
}

void InitFuzzTest(int* argc, char*** argv, std::string_view binary_id) {
  const char* centipede_binary = std::getenv("FUZZTEST_CENTIPEDE_BINARY");
  const bool is_runner_mode = std::getenv("CENTIPEDE_RUNNER_FLAGS");
  if (centipede_binary != nullptr && !is_runner_mode) {
    ExecvToCentipede(centipede_binary, *argc, *argv);
  }

  const bool is_listing = absl::GetFlag(FUZZTEST_FLAG(list_fuzz_tests));
  if (is_listing) {
    for (const auto& name : ListRegisteredTests()) {
      std::cout << "[*] Fuzz test: " << name << '\n';
    }
    std::exit(0);
  }

  const auto test_to_fuzz = absl::GetFlag(FUZZTEST_FLAG(fuzz));
  const bool is_test_to_fuzz_specified = test_to_fuzz != kUnspecified;
  if (is_test_to_fuzz_specified) {
    const std::string matching_fuzz_test =
        GetMatchingFuzzTestOrExit(test_to_fuzz);
    // Delegate the test to GoogleTest.
    GTEST_FLAG_SET(filter, matching_fuzz_test);
  }

  std::string derived_binary_id =
      binary_id.empty() ? std::string(internal::Basename(*argv[0]))
                        : std::string(binary_id);
  std::optional<std::string> reproduction_command_template;
  internal::Configuration configuration =
      CreateConfigurationsFromFlags(derived_binary_id);
  configuration.reproduction_command_template = reproduction_command_template;
  internal::RegisterFuzzTestsAsGoogleTests(argc, argv, configuration);

  const bool has_time_limit_per_test =
      configuration.time_limit_per_test < absl::InfiniteDuration();
  const RunMode run_mode = is_test_to_fuzz_specified || has_time_limit_per_test
                               ? RunMode::kFuzz
                               : RunMode::kUnitTest;

  if (run_mode == RunMode::kFuzz && !is_test_to_fuzz_specified &&
      GTEST_FLAG_GET(filter) == "*") {
    // Run only the fuzz tests, and not the unit tests when the user doesn't
    // set the test filter.
    // TODO: b/340232436 -- This is needed because we currently rely on a fuzz
    // test being the first test to run so that Centipede can get the serialized
    // configuration from the binary. For simplicity, we don't restrict the
    // filter to fuzz tests when the user explicitly sets the filter. Instead of
    // improving the logic here, once we fix b/340232436 we will remove this
    // altogether and allow a mix of fuzz tests and unit tests in all cases.
    GTEST_FLAG_SET(filter, absl::StrJoin(configuration.fuzz_tests, ":"));
  }

  // TODO(b/307513669): Use the Configuration class instead of Runtime.
  internal::Runtime::instance().SetRunMode(run_mode);
}

void ParseAbslFlags(int argc, char** argv) {
  std::vector<char*> positional_args;
  std::vector<absl::UnrecognizedFlag> unrecognized_flags;
  absl::ParseAbseilFlagsOnly(argc, argv, positional_args, unrecognized_flags);
}

}  // namespace fuzztest
