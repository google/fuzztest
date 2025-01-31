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

#include <sys/mman.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#else                      // __APPLE__
#include <linux/limits.h>  // ARG_MAX
#endif                     // __APPLE__
#include <fcntl.h>
#include <unistd.h>

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
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
#include "absl/log/log.h"
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
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/centipede_default_callbacks.h"
#include "./centipede/centipede_interface.h"
#include "./centipede/environment.h"
#include "./centipede/mutation_input.h"
#include "./centipede/runner_interface.h"
#include "./centipede/runner_result.h"
#include "./centipede/shared_memory_blob_sequence.h"
#include "./centipede/stop.h"
#include "./centipede/workdir.h"
#include "./common/defs.h"
#include "./common/temp_dir.h"
#include "./fuzztest/internal/any.h"
#include "./fuzztest/internal/configuration.h"
#include "./fuzztest/internal/domains/domain.h"
#include "./fuzztest/internal/fixture_driver.h"
#include "./fuzztest/internal/flag_name.h"
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

std::string ShellEscape(absl::string_view str) {
  return absl::StrCat("'", absl::StrReplaceAll(str, {{"'", "'\\''"}}), "'");
}

// TODO(xinhaoyuan): Consider passing rng seeds from the engine.
std::seed_seq GetRandomSeed() {
  const size_t seed = time(nullptr) + getpid() +
                      std::hash<std::thread::id>{}(std::this_thread::get_id());
  return std::seed_seq({seed, seed >> 32});
}

centipede::Environment CreateDefaultCentipedeEnvironment() {
  centipede::Environment env;
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

centipede::Environment CreateCentipedeEnvironmentFromConfiguration(
    const Configuration& configuration, absl::string_view workdir,
    absl::string_view test_name, RunMode run_mode) {
  centipede::Environment env = CreateDefaultCentipedeEnvironment();
  constexpr absl::Duration kUnitTestDefaultDuration = absl::Seconds(3);
  env.fuzztest_single_test_mode = true;
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
  absl::StrAppend(&env.binary,
                  " --" FUZZTEST_FLAG_PREFIX
                  "internal_override_total_time_limit=",
                  total_time_limit);
  env.coverage_binary = (*args)[0];
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

class CentipedeAdaptorRunnerCallbacks : public centipede::RunnerCallbacks {
 public:
  CentipedeAdaptorRunnerCallbacks(Runtime* runtime,
                                  FuzzTestFuzzerImpl* fuzzer_impl,
                                  const Configuration* configuration)
      : runtime_(*runtime),
        fuzzer_impl_(*fuzzer_impl),
        configuration_(*configuration),
        cmp_tables_(std::make_unique<TablesOfRecentCompares>()),
        prng_(GetRandomSeed()) {}

  bool Execute(centipede::ByteSpan input) override {
    if (!domain_setup_is_checked_) {
      // Create a new domain input to trigger any domain setup
      // failures here. (e.g. Ineffective Filter)
      fuzzer_impl_.params_domain_.Init(prng_);
      domain_setup_is_checked_ = true;
    }

    auto parsed_input =
        fuzzer_impl_.TryParse({(char*)input.data(), input.size()});
    if (parsed_input.ok()) {
      fuzzer_impl_.RunOneInput({*std::move(parsed_input)});
      return true;
    }
    return false;
  }

  void GetSeeds(
      std::function<void(centipede::ByteSpan)> seed_callback) override {
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
      seed_callback(centipede::AsByteSpan(seed_serialized));
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

  bool Mutate(
      const std::vector<centipede::MutationInputRef>& inputs,
      size_t num_mutants,
      std::function<void(centipede::ByteSpan)> new_mutant_callback) override {
    if (inputs.empty()) return false;
    if (runtime_.run_mode() == RunMode::kFuzz) SetMetadata(inputs[0].metadata);
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
        const auto& origin =
            inputs[absl::Uniform<size_t>(prng_, 0, inputs.size())].data;
        auto parsed_origin =
            fuzzer_impl_.TryParse({(const char*)origin.data(), origin.size()});
        if (!parsed_origin.ok()) {
          parsed_origin = fuzzer_impl_.params_domain_.Init(prng_);
        }
        auto mutant = FuzzTestFuzzerImpl::Input{*std::move(parsed_origin)};
        fuzzer_impl_.MutateValue(mutant, prng_,
                                 {.cmp_tables = cmp_tables_.get()});
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
  void InsertCmpEntryIntoIntegerDictionary(const uint8_t* a, const uint8_t* b) {
    T a_int;
    T b_int;
    memcpy(&a_int, a, sizeof(T));
    memcpy(&b_int, b, sizeof(T));
    cmp_tables_->GetMutable<sizeof(T)>().Insert(a_int, b_int);
  }

  void SetMetadata(const centipede::ExecutionMetadata* metadata) {
    if (metadata == nullptr) return;
    metadata->ForEachCmpEntry(
        [this](centipede::ByteSpan a, centipede::ByteSpan b) {
          FUZZTEST_INTERNAL_CHECK(a.size() == b.size(),
                                  "cmp operands must have the same size");
          const size_t size = a.size();
          if (size < kMinCmpEntrySize) return;
          if (size > kMaxCmpEntrySize) return;
          if (size == 2) {
            InsertCmpEntryIntoIntegerDictionary<uint16_t>(a.data(), b.data());
          } else if (size == 4) {
            InsertCmpEntryIntoIntegerDictionary<uint32_t>(a.data(), b.data());
          } else if (size == 8) {
            InsertCmpEntryIntoIntegerDictionary<uint64_t>(a.data(), b.data());
          }
          cmp_tables_->GetMutable<0>().Insert(a.data(), b.data(), size);
        });
  }

  // Size limits on the cmp entries to be used in mutation.
  static constexpr uint8_t kMaxCmpEntrySize = 15;
  static constexpr uint8_t kMinCmpEntrySize = 2;

  Runtime& runtime_;
  FuzzTestFuzzerImpl& fuzzer_impl_;
  const Configuration& configuration_;
  bool domain_setup_is_checked_ = false;
  std::unique_ptr<TablesOfRecentCompares> cmp_tables_;
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
    const int64_t time_limit_seconds =
        absl::ToInt64Seconds(configuration.time_limit_per_input);
    if (time_limit_seconds <= 0) {
      absl::FPrintF(
          GetStderr(),
          "[!] Skip setting per-input time limit that is too short: %s\n",
          absl::FormatDuration(configuration.time_limit_per_input));
    } else {
      absl::FPrintF(GetStderr(),
                    "[.] Per-input time limit set to: %" PRId64 "s\n",
                    time_limit_seconds);
      CentipedeSetTimeoutPerInput(time_limit_seconds);
    }
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

  void SetUpFuzzTest() override {
    orig_fixture_driver_->SetUpFuzzTest();
    FUZZTEST_INTERNAL_CHECK(configuration_ != nullptr,
                            "Setting up a fuzz test without configuration!");
    PopulateTestLimitsToCentipedeRunner(*configuration_);
  }

  void SetUpIteration() override {
    if (!runner_mode) CentipedePrepareProcessing();
    orig_fixture_driver_->SetUpIteration();
  }

  void TearDownIteration() override {
    orig_fixture_driver_->TearDownIteration();
    if (runtime_.skipping_requested()) {
      CentipedeSetExecutionResult(nullptr, 0);
    }
    CentipedeFinalizeProcessing();
  }

  void TearDownFuzzTest() override { orig_fixture_driver_->TearDownFuzzTest(); }

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
  const bool runner_mode = std::getenv("CENTIPEDE_RUNNER_FLAGS") != nullptr;
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

// TODO(xinhaoyuan): Consider merging `mode` into `configuration`.
bool CentipedeFuzzerAdaptor::Run(int* argc, char*** argv, RunMode mode,
                                 const Configuration& configuration) {
  centipede_fixture_driver_->set_configuration(&configuration);
  // When the CENTIPEDE_RUNNER_FLAGS env var exists, the current process is
  // considered a child process spawned by the Centipede binary as the runner,
  // and we should not run CentipedeMain in this process.
  const bool runner_mode = std::getenv("CENTIPEDE_RUNNER_FLAGS");
  const bool is_running_property_function_in_this_process =
      runner_mode || configuration.crashing_input_to_reproduce.has_value() ||
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
    runtime_.EnableReporter(&fuzzer_impl_.stats_, [] { return absl::Now(); });
  }
  fuzzer_impl_.fixture_driver_->SetUpFuzzTest();
  const int result = ([&]() {
    if (runtime_.skipping_requested()) {
      absl::FPrintF(GetStderr(),
                    "[.] Skipping %s per request from the test setup.\n",
                    test_.full_name());
      return 0;
    }
    if (runner_mode) {
      CentipedeAdaptorRunnerCallbacks runner_callbacks(&runtime_, &fuzzer_impl_,
                                                       &configuration);
      static char fake_argv0[] = "fake_argv";
      static char* fake_argv[] = {fake_argv0, nullptr};
      return centipede::RunnerMain(argc != nullptr ? *argc : 1,
                                   argv != nullptr ? *argv : fake_argv,
                                   runner_callbacks);
    }
    // Centipede engine does not support replay and reproducer minimization
    // (within the single process). So use the existing fuzztest implementation.
    // This is fine because it does not require coverage instrumentation.
    if (fuzzer_impl_.ReplayInputsIfAvailable(configuration)) return 0;
    // `ReplayInputsIfAvailable` overwrites the run mode - revert it back.
    runtime_.SetRunMode(mode);
    // Run as the fuzzing engine.
    std::unique_ptr<TempDir> workdir;
    if (configuration.corpus_database.empty() || mode == RunMode::kUnitTest)
      workdir = std::make_unique<TempDir>("fuzztest_workdir");
    const std::string workdir_path = workdir ? workdir->path() : "";
    const auto env = CreateCentipedeEnvironmentFromConfiguration(
        configuration, workdir_path, test_.full_name(), mode);
    centipede::DefaultCallbacksFactory<centipede::CentipedeDefaultCallbacks>
        factory;
    if (const char* minimize_dir_chars =
            std::getenv("FUZZTEST_MINIMIZE_TESTSUITE_DIR");
        configuration.corpus_database.empty() &&
        minimize_dir_chars != nullptr) {
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
          centipede::CentipedeMain(replay_env, factory) == 0,
          "Failed to replaying the testsuite for minimization");
      absl::FPrintF(GetStderr(), "[.] Imported the corpus from %s.\n",
                    minimize_dir);
      // 2. Run Centipede distillation on the shard.
      auto distill_env = env;
      distill_env.distill = true;
      FUZZTEST_INTERNAL_CHECK(
          centipede::CentipedeMain(distill_env, factory) == 0,
          "Failed to minimize the testsuite");
      absl::FPrintF(GetStderr(),
                    "[.] Minimized the corpus using Centipede distillation.\n");
      // 3. Replace the shard corpus data with the distillation result.
      auto workdir = centipede::WorkDir(distill_env);
      FUZZTEST_INTERNAL_CHECK(
          std::rename(workdir.DistilledCorpusFilePaths().MyShard().c_str(),
                      workdir.CorpusFilePaths().MyShard().c_str()) == 0,
          "Failed to replace the corpus data with the minimized result");
      // 4. Export the corpus of the shard.
      auto export_env = env;
      export_env.corpus_to_files = corpus_out_dir;
      FUZZTEST_INTERNAL_CHECK(
          centipede::CentipedeMain(export_env, factory) == 0,
          "Failed to export the corpus to FUZZTEST_MINIMIZE_TESTSUITE_DIR");
      absl::FPrintF(GetStderr(),
                    "[.] Exported the minimized the corpus to %s.\n",
                    corpus_out_dir);
      return 0;
    }
    return centipede::CentipedeMain(env, factory);
  })();
  fuzzer_impl_.fixture_driver_->TearDownFuzzTest();
  return result == 0;
}

}  // namespace fuzztest::internal

// The code below is used at very early stage of the process. Cannot use
// GetStderr().
namespace {

class CentipedeCallbacksForRunnerFlagsExtraction
    : public centipede::CentipedeCallbacks {
 public:
  using centipede::CentipedeCallbacks::CentipedeCallbacks;

  bool Execute(std::string_view binary,
               const std::vector<centipede::ByteArray>& inputs,
               centipede::BatchResult& batch_result) override {
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
  VLOG(1) << "[.] Centipede runner flags: " << runner_flags;
  return strdup(runner_flags.c_str());
}
