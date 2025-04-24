// Copyright 2023 Google LLC
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

#include "./fuzztest/internal/centipede_adaptor.h"

#ifdef __APPLE__
#include <sys/sysctl.h>
#else                      // __APPLE__
#include <linux/limits.h>  // ARG_MAX
#endif                     // __APPLE__
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>  // NOLINT
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <thread>  // NOLINT: For thread::get_id() only.
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/base/no_destructor.h"
#include "absl/functional/any_invocable.h"
#include "absl/log/absl_log.h"
#include "absl/memory/memory.h"
#include "absl/random/distributions.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/centipede_default_callbacks.h"
#include "./centipede/centipede_interface.h"
#include "./centipede/environment.h"
#include "./centipede/execution_metadata.h"
#include "./centipede/mutation_input.h"
#include "./centipede/runner_interface.h"
#include "./centipede/runner_result.h"
#include "./centipede/workdir.h"
#include "./common/defs.h"
#include "./common/temp_dir.h"
#include "./fuzztest/internal/any.h"
#include "./fuzztest/internal/configuration.h"
#include "./fuzztest/internal/domains/domain.h"
#include "./fuzztest/internal/fixture_driver.h"
#include "./fuzztest/internal/flag_name.h"
#include "./fuzztest/internal/io.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/runtime.h"
#include "./fuzztest/internal/table_of_recent_compares.h"

namespace fuzztest::internal {
namespace {

absl::StatusOr<std::vector<std::string>> GetProcessArgs() {
  std::vector<std::string> results;
#if defined(__APPLE__)
  // Reference:
  // https://chromium.googlesource.com/crashpad/crashpad/+/360e441c53ab4191a6fd2472cc57c3343a2f6944/util/posix/process_util_mac.cc
  char procargs[ARG_MAX];
  size_t procargs_size = sizeof(procargs);
  int mib[] = {CTL_KERN, KERN_PROCARGS2, getpid()};
  const int rv = sysctl(mib, sizeof(mib) / sizeof(mib[0]), procargs,
                        &procargs_size, nullptr, 0);
  if (rv != 0) {
    return absl::InternalError(
        "GetEnv: sysctl({CTK_KERN, KERN_PROCARGS2, ...}) failed");
  }
  if (procargs_size < sizeof(int)) {
    return absl::InternalError("GetEnv: procargs_size too small");
  }
  int argc = 0;
  std::memcpy(&argc, &procargs[0], sizeof(argc));
  size_t start_pos = sizeof(argc);
  // Find the end of the executable path.
  while (start_pos < procargs_size && procargs[start_pos] != 0) ++start_pos;
  if (start_pos == procargs_size) {
    return absl::NotFoundError("nothing after executable path");
  }
  // Find the beginning of the string area.
  while (start_pos < procargs_size && procargs[start_pos] == 0) ++start_pos;
  if (start_pos == procargs_size) {
    return absl::NotFoundError("nothing after executable path");
  }
  // Get the first argc c-strings without exceeding the boundary.
  for (int i = 0; i < argc; ++i) {
    const size_t current_argv_pos = start_pos;
    while (start_pos < procargs_size && procargs[start_pos] != 0) ++start_pos;
    if (start_pos == procargs_size) {
      return absl::InternalError("incomplete argv list in the procargs");
    }
    results.emplace_back(&procargs[current_argv_pos],
                         start_pos - current_argv_pos);
    ++start_pos;
  }
  return result;
#elif defined(__linux__)
  const int fd = open("/proc/self/cmdline", O_RDONLY);
  if (fd < 0) {
    return absl::InternalError(
        absl::StrCat("failed opening /proc/self/cmdline: ", strerror(errno)));
  }
  std::string args;
  while (true) {
    char buf[4096];
    const ssize_t read_size = read(fd, buf, sizeof(buf));
    if (read_size == 0) break;
    if (read_size < 0) {
      return absl::InternalError(
          absl::StrCat("failed reading /proc/self/cmdline: ", strerror(errno)));
    }
    args.append(buf, read_size);
  }
  if (close(fd) != 0) {
    return absl::InternalError(
        absl::StrCat("failed closing /proc/self/cmdline: ", strerror(errno)));
  }
  size_t start_pos = 0;
  while (start_pos < args.size()) {
    const size_t current_argv_pos = start_pos;
    while (start_pos < args.size() && args[start_pos] != 0) ++start_pos;
    results.emplace_back(&args[current_argv_pos], start_pos - current_argv_pos);
    ++start_pos;
  }
  return results;
#else  // !defined(__APPLE__) && !defined(__linux)
  return absl::UnimplementedError(
      absl::StrCat(__func__, "() not implemented on the platform"));
#endif
}

std::string GetSelfBinaryHashForCentipedeEnvironment() {
  static absl::NoDestructor<std::string> cached_self_binary_hash{[] {
    fuzztest::internal::Environment env;
    const auto args = GetProcessArgs();
    FUZZTEST_INTERNAL_CHECK(
        args.ok(), absl::StrCat("failed to get the original process args: ",
                                args.status()));
    env.coverage_binary = (*args)[0];
    env.UpdateBinaryHashIfEmpty();
    return env.binary_hash;
  }()};
  return *cached_self_binary_hash;
}

std::string ShellEscape(absl::string_view str) {
  return absl::StrCat("'", absl::StrReplaceAll(str, {{"'", "'\\''"}}), "'");
}

// TODO(xinhaoyuan): Consider passing rng seeds from the engine.
std::seed_seq GetRandomSeed() {
  const size_t seed = time(nullptr) + getpid() +
                      std::hash<std::thread::id>{}(std::this_thread::get_id());
  return std::seed_seq({seed, seed >> 32});
}

fuzztest::internal::Environment CreateDefaultCentipedeEnvironment() {
  fuzztest::internal::Environment env;
  // Will be set later using the test configuration.
  env.timeout_per_input = 0;
  // Will be set later using the test configuration.
  env.rss_limit_mb = 0;
  // Do not limit the address space as the fuzzing engine needs a
  // lot of address space. rss_limit_mb will be used for OOM
  // detection.
  env.address_space_limit_mb = 0;
  return env;
}

fuzztest::internal::Environment CreateCentipedeEnvironmentFromConfiguration(
    const Configuration& configuration, absl::string_view workdir,
    absl::string_view test_name, RunMode run_mode) {
  fuzztest::internal::Environment env = CreateDefaultCentipedeEnvironment();
  constexpr absl::Duration kUnitTestDefaultDuration = absl::Seconds(3);
  env.fuzztest_single_test_mode = true;
  if (configuration.time_limit_per_input < absl::InfiniteDuration()) {
    const int64_t time_limit_seconds =
        absl::ToInt64Seconds(configuration.time_limit_per_input);
    if (time_limit_seconds < 1) {
      absl::FPrintF(
          GetStderr(),
          "[!] Input time limit %s is too small - rounding up to one second\n",
          absl::StrCat(configuration.time_limit_per_input));
    }
    env.timeout_per_input = std::clamp<decltype(env.timeout_per_input)>(
        time_limit_seconds, 1,
        std::numeric_limits<decltype(env.timeout_per_input)>::max());
  }
  constexpr size_t kMiB = 1024 * 1024;
  FUZZTEST_INTERNAL_CHECK(configuration.rss_limit % kMiB == 0,
                          "configuration.rss_limit is not a multiple of MiB.");
  env.rss_limit_mb = configuration.rss_limit / kMiB;
  constexpr size_t kKiB = 1024;
  FUZZTEST_INTERNAL_CHECK(
      configuration.stack_limit % kKiB == 0,
      "configuration.stack_limit is not a multiple of KiB.");
  env.stack_limit_kb = configuration.stack_limit / kKiB;
  env.populate_binary_info = false;
  const auto args = GetProcessArgs();
  FUZZTEST_INTERNAL_CHECK(
      args.ok(),
      absl::StrCat("failed to get the original process args: ", args.status()));
  env.binary.clear();
  for (const auto& arg : *args) {
    // We need shell escaping, because env.binary will be passed to system(),
    // which uses the default shell.
    absl::StrAppend(&env.binary, env.binary.empty() ? "" : " ",
                    ShellEscape(arg));
  }
  absl::StrAppend(
      &env.binary,
      " --" FUZZTEST_FLAG_PREFIX "internal_override_fuzz_test=", test_name);
  absl::Duration total_time_limit = configuration.GetTimeLimitPerTest();
  // TODO(xinhaoyuan): Consider using unset optional duration instead of zero
  // duration as the special value.
  if (total_time_limit == absl::ZeroDuration() &&
      run_mode == RunMode::kUnitTest) {
    total_time_limit = kUnitTestDefaultDuration;
  }
  {
    Configuration single_test_configuration = configuration;
    single_test_configuration.fuzz_tests_in_current_shard = {
        std::string{test_name}};
    single_test_configuration.time_limit = total_time_limit;
    single_test_configuration.time_budget_type = TimeBudgetType::kTotal;
    env.fuzztest_configuration = single_test_configuration.Serialize();
  }

  absl::StrAppend(&env.binary,
                  " --" FUZZTEST_FLAG_PREFIX
                  "internal_override_total_time_limit=",
                  total_time_limit);
  if (configuration.crashing_input_to_reproduce.has_value()) {
    absl::StrAppend(&env.binary,
                    " --" FUZZTEST_FLAG_PREFIX
                    "internal_crashing_input_to_reproduce=",
                    *configuration.crashing_input_to_reproduce);
    env.crash_id = *configuration.crashing_input_to_reproduce;
    env.replay_crash = true;
  }
  env.coverage_binary = (*args)[0];
  env.binary_name = std::filesystem::path{(*args)[0]}.filename();
  env.binary_hash = GetSelfBinaryHashForCentipedeEnvironment();
  env.exit_on_crash =
      // Do shallow testing when running in unit-test mode unless we are replay
      // coverage inputs.
      (run_mode == RunMode::kUnitTest &&
       !configuration.replay_coverage_inputs) ||
      // When not using a corpus database, keep the same behavior as the legacy
      // single-process mode.
      configuration.corpus_database.empty() ||
      // No need to keep running when replaying crashing input.
      configuration.crashing_input_to_reproduce.has_value();
  env.print_runner_log = configuration.print_subprocess_log;
  env.workdir = workdir;
  if (configuration.corpus_database.empty()) {
    if (total_time_limit != absl::InfiniteDuration()) {
      absl::FPrintF(GetStderr(), "[.] Fuzzing timeout set to: %s\n",
                    absl::FormatDuration(total_time_limit));
      env.stop_at = absl::Now() + total_time_limit;
    }
    env.first_corpus_dir_output_only = true;
    if (const char* corpus_out_dir_chars =
            std::getenv("FUZZTEST_TESTSUITE_OUT_DIR")) {
      env.corpus_dir.push_back(corpus_out_dir_chars);
    } else {
      env.corpus_dir.push_back("");
    }
    if (const char* corpus_in_dir_chars =
            std::getenv("FUZZTEST_TESTSUITE_IN_DIR")) {
      env.corpus_dir.push_back(corpus_in_dir_chars);
    }
    if (const char* max_fuzzing_runs =
            std::getenv("FUZZTEST_MAX_FUZZING_RUNS")) {
      if (!absl::SimpleAtoi(max_fuzzing_runs, &env.num_runs)) {
        absl::FPrintF(
            GetStderr(),
            "[!] Cannot parse env FUZZTEST_MAX_FUZZING_RUNS=%s - will "
            "not limit fuzzing runs.\n",
            max_fuzzing_runs);
        env.num_runs = std::numeric_limits<size_t>::max();
      }
    }
  } else {
    // Not setting env.stop_at since current update_corpus logic in Centipede
    // would propagate that.
    if (std::getenv("FUZZTEST_TESTSUITE_OUT_DIR")) {
      absl::FPrintF(GetStderr(),
                    "[!] Ignoring FUZZTEST_TESTSUITE_OUT_DIR when the corpus "
                    "database is set.\n");
    }
    if (std::getenv("FUZZTEST_TESTSUITE_IN_DIR")) {
      absl::FPrintF(GetStderr(),
                    "[!] Ignoring FUZZTEST_TESTSUITE_IN_DIR when the corpus "
                    "database is set.\n");
    }
    if (std::getenv("FUZZTEST_MINIMIZE_TESTSUITE_DIR")) {
      absl::FPrintF(GetStderr(),
                    "[!] Ignoring FUZZTEST_MINIMIZE_TESTSUITE_DIR when the "
                    "corpus database is set.\n");
    }
    if (const char* max_fuzzing_runs =
            std::getenv("FUZZTEST_MAX_FUZZING_RUNS")) {
      absl::FPrintF(GetStderr(),
                    "[!] Ignoring FUZZTEST_MAX_FUZZING_RUNS when the "
                    "corpus database is set.\n");
    }
  }
  return env;
}

}  // namespace

bool IsCentipedeRunner() {
  return std::getenv("CENTIPEDE_RUNNER_FLAGS") != nullptr;
}

std::vector<std::string> ListCrashIdsUsingCentipede(
    const Configuration& configuration, absl::string_view test_name) {
  // Do not invoke Centipede to list crashes as a runner, which is also
  // unnecessary.
  if (IsCentipedeRunner()) return {};
  std::vector<std::string> results;
  TempDir workspace("/tmp/fuzztest-");
  auto env = CreateCentipedeEnvironmentFromConfiguration(
      configuration, /*workdir=*/"", test_name, Runtime::instance().run_mode());
  env.list_crash_ids = true;
  env.list_crash_ids_file =
      std::filesystem::path{workspace.path()} / "crash_ids";

  DefaultCallbacksFactory<CentipedeDefaultCallbacks> callbacks;
  const int centipede_ret = CentipedeMain(env, callbacks);
  if (centipede_ret != EXIT_SUCCESS) {
    absl::FPrintF(GetStderr(),
                  "[!] Cannot list crash IDs using Centipede - returning "
                  "empty results.");
    return {};
  }
  const auto contents = ReadFile(env.list_crash_ids_file);
  if (!contents.has_value()) {
    absl::FPrintF(GetStderr(),
                  "[!] Cannot read the result file from listing crash IDs "
                  "with Centipede - returning empty results.");
    return {};
  }
  if (contents->empty()) {
    return {};
  }
  return absl::StrSplit(*contents, '\n');
}

class CentipedeAdaptorRunnerCallbacks
    : public fuzztest::internal::RunnerCallbacks {
 public:
  CentipedeAdaptorRunnerCallbacks(Runtime* runtime,
                                  FuzzTestFuzzerImpl* fuzzer_impl,
                                  const Configuration* configuration)
      : runtime_(*runtime),
        fuzzer_impl_(*fuzzer_impl),
        configuration_(*configuration),
        prng_(GetRandomSeed()) {}

  bool Execute(fuzztest::internal::ByteSpan input) override {
    // We should avoid doing anything other than executing the input here so
    // that we don't affect the execution time.
    auto parsed_input =
        fuzzer_impl_.TryParse({(char*)input.data(), input.size()});
    if (parsed_input.ok()) {
      fuzzer_impl_.RunOneInput({*std::move(parsed_input)});
      return true;
    }
    return false;
  }

  void GetSeeds(std::function<void(fuzztest::internal::ByteSpan)> seed_callback)
      override {
    std::vector<GenericDomainCorpusType> seeds =
        fuzzer_impl_.fixture_driver_->GetSeeds();
    constexpr int kInitialValuesInSeeds = 32;
    for (int i = 0; i < kInitialValuesInSeeds; ++i) {
      seeds.push_back(fuzzer_impl_.params_domain_.Init(prng_));
    }
    absl::c_shuffle(seeds, prng_);
    for (const auto& seed : seeds) {
      const auto seed_serialized =
          fuzzer_impl_.params_domain_.SerializeCorpus(seed).ToString();
      seed_callback(fuzztest::internal::AsByteSpan(seed_serialized));
    }
  }

  std::string GetSerializedTargetConfig() override {
    return configuration_.Serialize();
  }

  void OnFailure(std::function<void(std::string_view)>
                     failure_description_callback) override {
    // We register the callback only once. This is because `runtime_` is a
    // global singleton object, and hence previously registered callbacks remain
    // in the registry. In normal circumstances, there should be only one
    // runner callback object and a single call to this method, but there are
    // corner cases when multiple runner callback objects are created, e.g.,
    // when Centipede runs multiple fuzz tests in the multi-process mode.
    [[maybe_unused]] static bool callback_registered =
        [this, failure_description_callback =
                   std::move(failure_description_callback)]() mutable {
          runtime_.RegisterCrashMetadataListener(
              [failure_description_callback =
                   std::move(failure_description_callback)](
                  absl::string_view crash_type,
                  absl::Span<const std::string> /*stack_frames*/) {
                failure_description_callback(
                    {crash_type.data(), crash_type.size()});
              });
          return true;
        }();
  }

  bool HasCustomMutator() const override { return true; }

  bool Mutate(const std::vector<fuzztest::internal::MutationInputRef>& inputs,
              size_t num_mutants,
              std::function<void(fuzztest::internal::ByteSpan)>
                  new_mutant_callback) override {
    if (inputs.empty()) return false;
    std::vector<std::unique_ptr<TablesOfRecentCompares>> input_cmp_tables(
        inputs.size());
    for (size_t i = 0; i < num_mutants; ++i) {
      const auto choice = absl::Uniform<double>(prng_, 0, 1);
      std::string mutant_data;
      constexpr double kDomainInitRatio = 0.0001;
      if (choice < kDomainInitRatio) {
        mutant_data =
            fuzzer_impl_.params_domain_
                .SerializeCorpus(fuzzer_impl_.params_domain_.Init(prng_))
                .ToString();
      } else {
        const auto origin_index =
            absl::Uniform<size_t>(prng_, 0, inputs.size());
        const auto& origin = inputs[origin_index].data;
        auto parsed_origin =
            fuzzer_impl_.TryParse({(const char*)origin.data(), origin.size()});
        if (!parsed_origin.ok()) {
          parsed_origin = fuzzer_impl_.params_domain_.Init(prng_);
        }
        auto mutant = FuzzTestFuzzerImpl::Input{*std::move(parsed_origin)};
        if (runtime_.run_mode() == RunMode::kFuzz &&
            input_cmp_tables[origin_index] == nullptr) {
          input_cmp_tables[origin_index] =
              std::make_unique<TablesOfRecentCompares>();
          PopulateMetadata(inputs[origin_index].metadata,
                           *input_cmp_tables[origin_index]);
        }
        fuzzer_impl_.MutateValue(mutant, prng_,
                                 {input_cmp_tables[origin_index].get()});
        mutant_data =
            fuzzer_impl_.params_domain_.SerializeCorpus(mutant.args).ToString();
      }
      new_mutant_callback(
          {(unsigned char*)mutant_data.data(), mutant_data.size()});
    }
    return true;
  }

  ~CentipedeAdaptorRunnerCallbacks() override { runtime_.UnsetCurrentArgs(); }

 private:
  template <typename T>
  static void InsertCmpEntryIntoIntegerDictionary(
      const uint8_t* a, const uint8_t* b, TablesOfRecentCompares& cmp_tables) {
    T a_int;
    T b_int;
    memcpy(&a_int, a, sizeof(T));
    memcpy(&b_int, b, sizeof(T));
    cmp_tables.GetMutable<sizeof(T)>().Insert(a_int, b_int);
  }

  static void PopulateMetadata(
      const fuzztest::internal::ExecutionMetadata* metadata,
      TablesOfRecentCompares& cmp_tables) {
    if (metadata == nullptr) return;
    metadata->ForEachCmpEntry(
        [&cmp_tables](fuzztest::internal::ByteSpan a,
                      fuzztest::internal::ByteSpan b) {
          FUZZTEST_INTERNAL_CHECK(a.size() == b.size(),
                                  "cmp operands must have the same size");
          const size_t size = a.size();
          if (size < kMinCmpEntrySize) return;
          if (size > kMaxCmpEntrySize) return;
          if (size == 2) {
            InsertCmpEntryIntoIntegerDictionary<uint16_t>(a.data(), b.data(),
                                                          cmp_tables);
          } else if (size == 4) {
            InsertCmpEntryIntoIntegerDictionary<uint32_t>(a.data(), b.data(),
                                                          cmp_tables);
          } else if (size == 8) {
            InsertCmpEntryIntoIntegerDictionary<uint64_t>(a.data(), b.data(),
                                                          cmp_tables);
          }
          cmp_tables.GetMutable<0>().Insert(a.data(), b.data(), size);
        });
  }

  // Size limits on the cmp entries to be used in mutation.
  static constexpr uint8_t kMaxCmpEntrySize = 15;
  static constexpr uint8_t kMinCmpEntrySize = 2;

  Runtime& runtime_;
  FuzzTestFuzzerImpl& fuzzer_impl_;
  const Configuration& configuration_;
  absl::BitGen prng_;
};

namespace {

void PopulateTestLimitsToCentipedeRunner(const Configuration& configuration) {
  if (const size_t stack_limit =
          GetStackLimitFromEnvOrConfiguration(configuration);
      stack_limit > 0) {
    absl::FPrintF(GetStderr(), "[.] Stack limit set to: %zu\n", stack_limit);
    CentipedeSetStackLimit(/*stack_limit_kb=*/stack_limit >> 10);
  }
  if (configuration.rss_limit > 0) {
    absl::FPrintF(GetStderr(), "[.] RSS limit set to: %zu\n",
                  configuration.rss_limit);
    CentipedeSetRssLimit(/*rss_limit_mb=*/configuration.rss_limit >> 20);
  }
  if (configuration.time_limit_per_input < absl::InfiniteDuration()) {
    int64_t time_limit_seconds =
        absl::ToInt64Seconds(configuration.time_limit_per_input);
    if (time_limit_seconds < 1) {
      absl::FPrintF(
          GetStderr(),
          "[!] Input time limit %s is too small - rounding up to one second\n",
          absl::StrCat(configuration.time_limit_per_input));
      time_limit_seconds = 1;
    }
    absl::FPrintF(GetStderr(),
                  "[.] Per-input time limit set to: %" PRId64 "s\n",
                  time_limit_seconds);
    CentipedeSetTimeoutPerInput(time_limit_seconds);
  }
}

}  // namespace

class CentipedeFixtureDriver : public UntypedFixtureDriver {
 public:
  CentipedeFixtureDriver(
      Runtime& runtime,
      std::unique_ptr<UntypedFixtureDriver> orig_fixture_driver)
      : runtime_(runtime),
        orig_fixture_driver_(std::move(orig_fixture_driver)) {}

  void RunFuzzTest(absl::AnyInvocable<void() &&> run_fuzz_test_once) override {
    orig_fixture_driver_->RunFuzzTest([&, this] {
      FUZZTEST_INTERNAL_CHECK(configuration_ != nullptr,
                              "Setting up a fuzz test without configuration!");
      PopulateTestLimitsToCentipedeRunner(*configuration_);
      std::move(run_fuzz_test_once)();
    });
  }

  void RunFuzzTestIteration(
      absl::AnyInvocable<void() &&> run_iteration_once) override {
    orig_fixture_driver_->RunFuzzTestIteration([&, this] {
      if (!runner_mode) CentipedePrepareProcessing();
      std::move(run_iteration_once)();
    });
    if (runtime_.skipping_requested()) {
      CentipedeSetExecutionResult(nullptr, 0);
    }
    CentipedeFinalizeProcessing();
  }

  void Test(MoveOnlyAny&& args_untyped) const override {
    orig_fixture_driver_->Test(std::move(args_untyped));
  }

  std::vector<GenericDomainCorpusType> GetSeeds() const override {
    return orig_fixture_driver_->GetSeeds();
  }

  UntypedDomain GetDomains() const override {
    return orig_fixture_driver_->GetDomains();
  }

  void set_configuration(const Configuration* configuration) {
    configuration_ = configuration;
  }

 private:
  const Configuration* configuration_ = nullptr;
  Runtime& runtime_;
  const bool runner_mode = IsCentipedeRunner();
  std::unique_ptr<UntypedFixtureDriver> orig_fixture_driver_;
};

CentipedeFuzzerAdaptor::CentipedeFuzzerAdaptor(
    const FuzzTest& test, std::unique_ptr<UntypedFixtureDriver> fixture_driver)
    : test_(test),
      centipede_fixture_driver_(
          new CentipedeFixtureDriver(runtime_, std::move(fixture_driver))),
      fuzzer_impl_(test_, absl::WrapUnique(centipede_fixture_driver_)) {
  FUZZTEST_INTERNAL_CHECK(centipede_fixture_driver_ != nullptr,
                          "Invalid fixture driver!");
}

bool CentipedeFuzzerAdaptor::RunInUnitTestMode(
    const Configuration& configuration) {
  return Run(/*argc=*/nullptr, /*argv=*/nullptr, RunMode::kUnitTest,
             configuration);
}

bool CentipedeFuzzerAdaptor::RunInFuzzingMode(
    int* argc, char*** argv, const Configuration& configuration) {
  return Run(argc, argv, RunMode::kFuzz, configuration);
}

bool CentipedeFuzzerAdaptor::ReplayCrashInSingleProcess(
    const Configuration& configuration) {
  fuzztest::internal::DefaultCallbacksFactory<
      fuzztest::internal::CentipedeDefaultCallbacks>
      factory;
  TempDir crash_export_dir("fuzztest_crash");
  auto export_crash_env = CreateCentipedeEnvironmentFromConfiguration(
      configuration, /*workdir=*/"", test_.full_name(), runtime_.run_mode());
  std::string crash_file =
      (std::filesystem::path(crash_export_dir.path()) / "crash").string();
  export_crash_env.export_crash_file = crash_file;
  export_crash_env.replay_crash = false;
  export_crash_env.export_crash = true;
  if (fuzztest::internal::CentipedeMain(export_crash_env, factory) !=
      EXIT_SUCCESS) {
    absl::FPrintF(
        GetStderr(),
        "[!] Encountered error when using Centipede to export the crash "
        "input.");
    return false;
  }
  CentipedeAdaptorRunnerCallbacks runner_callbacks(&runtime_, &fuzzer_impl_,
                                                   &configuration);
  static char replay_argv0[] = "replay_argv";
  char* replay_argv[] = {replay_argv0, crash_file.data()};

  int result = 0;
  fuzzer_impl_.fixture_driver_->RunFuzzTest([&] {
    result = fuzztest::internal::RunnerMain(/*argc=*/2, replay_argv,
                                            runner_callbacks);
  });
  return result == 0;
}

// TODO(xinhaoyuan): Consider merging `mode` into `configuration`.
bool CentipedeFuzzerAdaptor::Run(int* argc, char*** argv, RunMode mode,
                                 const Configuration& configuration) {
  centipede_fixture_driver_->set_configuration(&configuration);
  // When the CENTIPEDE_RUNNER_FLAGS env var exists, the current process is
  // considered a child process spawned by the Centipede binary as the runner,
  // and we should not run CentipedeMain in this process.
  const bool runner_mode = IsCentipedeRunner();
  const bool is_running_property_function_in_this_process =
      runner_mode ||
      (configuration.crashing_input_to_reproduce.has_value() &&
       configuration.replay_in_single_process) ||
      std::getenv("FUZZTEST_REPLAY") ||
      std::getenv("FUZZTEST_MINIMIZE_REPRODUCER");
  if (!is_running_property_function_in_this_process &&
      runtime_.termination_requested()) {
    absl::FPrintF(GetStderr(),
                  "[.] Skipping %s since termination was requested.\n",
                  test_.full_name());
    runtime_.SetSkippingRequested(true);
    return true;
  }
  runtime_.SetRunMode(mode);
  runtime_.SetSkippingRequested(false);
  runtime_.SetCurrentTest(&test_, &configuration);
  if (is_running_property_function_in_this_process) {
    if (IsSilenceTargetEnabled()) SilenceTargetStdoutAndStderr();
    // TODO(b/393582695): Consider whether we need some kind of reporting
    // enabled in the controller mode to handle test setup failures.
    runtime_.EnableReporter(&fuzzer_impl_.stats_, [] { return absl::Now(); });
  }
  if (!configuration.corpus_database.empty() &&
      configuration.crashing_input_to_reproduce.has_value() &&
      configuration.replay_in_single_process) {
    return ReplayCrashInSingleProcess(configuration);
  }
  int result = EXIT_FAILURE;
  bool to_run_controller = false;
  fuzzer_impl_.fixture_driver_->RunFuzzTest([&, this]() {
    if (runtime_.skipping_requested()) {
      absl::FPrintF(GetStderr(),
                    "[.] Skipping %s per request from the test setup.\n",
                    test_.full_name());
      result = 0;
      return;
    }
    if (runner_mode) {
      CentipedeAdaptorRunnerCallbacks runner_callbacks(&runtime_, &fuzzer_impl_,
                                                       &configuration);
      static char fake_argv0[] = "fake_argv";
      static char* fake_argv[] = {fake_argv0, nullptr};
      result = fuzztest::internal::RunnerMain(
          argc != nullptr ? *argc : 1, argv != nullptr ? *argv : fake_argv,
          runner_callbacks);
      return;
    }
    // Centipede engine does not support replay and reproducer minimization
    // (within the single process). So use the existing fuzztest implementation.
    // This is fine because it does not require coverage instrumentation.
    if (!configuration.crashing_input_to_reproduce.has_value() &&
        fuzzer_impl_.ReplayInputsIfAvailable(configuration)) {
      result = 0;
      return;
    }
    // `ReplayInputsIfAvailable` overwrites the run mode - revert it back.
    runtime_.SetRunMode(mode);
    to_run_controller = true;
  });
  if (!to_run_controller) return result == 0;
  // Run as the fuzzing engine.
  [&] {
    runtime_.SetShouldTerminateOnNonFatalFailure(false);
    std::unique_ptr<TempDir> workdir;
    if (configuration.corpus_database.empty() || mode == RunMode::kUnitTest)
      workdir = std::make_unique<TempDir>("fuzztest_workdir");
    const std::string workdir_path = workdir ? workdir->path() : "";
    const auto env = CreateCentipedeEnvironmentFromConfiguration(
        configuration, workdir_path, test_.full_name(), mode);
    fuzztest::internal::DefaultCallbacksFactory<
        fuzztest::internal::CentipedeDefaultCallbacks>
        factory;
    if (const char* minimize_dir_chars =
            std::getenv("FUZZTEST_MINIMIZE_TESTSUITE_DIR")) {
      const std::string minimize_dir = minimize_dir_chars;
      const char* corpus_out_dir_chars =
          std::getenv("FUZZTEST_TESTSUITE_OUT_DIR");
      FUZZTEST_INTERNAL_CHECK(corpus_out_dir_chars != nullptr,
                              "FUZZTEST_TESTSUITE_OUT_DIR must be specified "
                              "when minimizing testsuite");
      const std::string corpus_out_dir = corpus_out_dir_chars;
      absl::FPrintF(
          GetStderr(),
          "[!] WARNING: Minimization via FUZZTEST_MINIMIZE_TESTSUITE_DIR is "
          "intended for compatibility with certain fuzzing infrastructures. "
          "End users are strongly advised against using it directly.\n");
      // Minimization with Centipede takes multiple steps:
      // 1. Load the corpus into the Centipede shard.
      auto replay_env = env;
      // The first empty path means no output dir.
      replay_env.corpus_dir = {"", minimize_dir};
      replay_env.load_shards_only = true;
      FUZZTEST_INTERNAL_CHECK(
          fuzztest::internal::CentipedeMain(replay_env, factory) == 0,
          "Failed to replaying the testsuite for minimization");
      absl::FPrintF(GetStderr(), "[.] Imported the corpus from %s.\n",
                    minimize_dir);
      // 2. Run Centipede distillation on the shard.
      auto distill_env = env;
      distill_env.distill = true;
      FUZZTEST_INTERNAL_CHECK(
          fuzztest::internal::CentipedeMain(distill_env, factory) == 0,
          "Failed to minimize the testsuite");
      absl::FPrintF(GetStderr(),
                    "[.] Minimized the corpus using Centipede distillation.\n");
      // 3. Replace the shard corpus data with the distillation result.
      auto workdir = fuzztest::internal::WorkDir(distill_env);
      FUZZTEST_INTERNAL_CHECK(
          std::rename(workdir.DistilledCorpusFilePaths().MyShard().c_str(),
                      workdir.CorpusFilePaths().MyShard().c_str()) == 0,
          "Failed to replace the corpus data with the minimized result");
      // 4. Export the corpus of the shard.
      auto export_env = env;
      export_env.corpus_to_files = corpus_out_dir;
      FUZZTEST_INTERNAL_CHECK(
          fuzztest::internal::CentipedeMain(export_env, factory) == 0,
          "Failed to export the corpus to FUZZTEST_MINIMIZE_TESTSUITE_DIR");
      absl::FPrintF(GetStderr(),
                    "[.] Exported the minimized the corpus to %s.\n",
                    corpus_out_dir);
      result = 0;
      return;
    }
    result = fuzztest::internal::CentipedeMain(env, factory);
  }();
  return result == 0;
}

}  // namespace fuzztest::internal

// The code below is used at very early stage of the process. Cannot use
// GetStderr().
namespace {

class CentipedeCallbacksForRunnerFlagsExtraction
    : public fuzztest::internal::CentipedeCallbacks {
 public:
  using fuzztest::internal::CentipedeCallbacks::CentipedeCallbacks;

  bool Execute(std::string_view binary,
               const std::vector<fuzztest::internal::ByteArray>& inputs,
               fuzztest::internal::BatchResult& batch_result) override {
    return false;
  }

  std::string GetRunnerFlagsContent() {
    constexpr absl::string_view kRunnerFlagPrefix = "CENTIPEDE_RUNNER_FLAGS=";
    const std::string runner_flags = ConstructRunnerFlags();
    if (!absl::StartsWith(runner_flags, kRunnerFlagPrefix)) {
      absl::FPrintF(
          stderr,
          "[!] Unexpected prefix in Centipede runner flags - returning "
          "without stripping the prefix.\n");
      return runner_flags;
    }
    return runner_flags.substr(kRunnerFlagPrefix.size());
  }
};

}  // namespace

extern "C" const char* CentipedeGetRunnerFlags() {
  if (const char* runner_flags_env = std::getenv("CENTIPEDE_RUNNER_FLAGS")) {
    // Runner mode. Use the existing flags.
    return strdup(runner_flags_env);
  }

  // Set the runner flags according to the FuzzTest default environment.
  const auto env = fuzztest::internal::CreateDefaultCentipedeEnvironment();
  CentipedeCallbacksForRunnerFlagsExtraction callbacks(env);
  const std::string runner_flags = callbacks.GetRunnerFlagsContent();
  ABSL_VLOG(1) << "[.] Centipede runner flags: " << runner_flags;
  return strdup(runner_flags.c_str());
}
