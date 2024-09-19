// Copyright 2022 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./centipede/centipede_interface.h"

#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>  // NOLINT
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/base/optimization.h"
#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./centipede/analyze_corpora.h"
#include "./centipede/binary_info.h"
#include "./centipede/centipede.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/command.h"
#include "./centipede/coverage.h"
#include "./centipede/distill.h"
#include "./centipede/early_exit.h"
#include "./centipede/environment.h"
#include "./centipede/minimize_crash.h"
#include "./centipede/pc_info.h"
#include "./centipede/periodic_action.h"
#include "./centipede/runner_result.h"
#include "./centipede/seed_corpus_maker_lib.h"
#include "./centipede/stats.h"
#include "./centipede/thread_pool.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"
#include "./common/blob_file.h"
#include "./common/defs.h"
#include "./common/hash.h"
#include "./common/logging.h"  // IWYU pragma: keep
#include "./common/remote_file.h"
#include "./common/status_macros.h"
#include "./fuzztest/internal/configuration.h"

namespace centipede {

namespace {

// Sets signal handler for SIGINT and SIGALRM.
void SetSignalHandlers(absl::Time stop_at) {
  for (int signum : {SIGINT, SIGALRM}) {
    struct sigaction sigact = {};
    sigact.sa_handler = [](int received_signum) {
      if (received_signum == SIGINT) {
        ABSL_RAW_LOG(INFO, "Ctrl-C pressed: winding down");
        RequestEarlyExit(EXIT_FAILURE);  // => abnormal outcome
      } else if (received_signum == SIGALRM) {
        ABSL_RAW_LOG(INFO, "Reached --stop_at time: winding down");
        RequestEarlyExit(EXIT_SUCCESS);  // => expected outcome
      } else {
        ABSL_UNREACHABLE();
      }
    };
    sigaction(signum, &sigact, nullptr);
  }

  if (stop_at != absl::InfiniteFuture()) {
    const absl::Duration stop_in = stop_at - absl::Now();
    // Setting an alarm works only if the delay is longer than 1 second.
    if (stop_in >= absl::Seconds(1)) {
      LOG(INFO) << "Setting alarm for --stop_at time " << stop_at << " (in "
                << stop_in << ")";
      PCHECK(alarm(absl::ToInt64Seconds(stop_in)) == 0) << "Alarm already set";
    } else {
      LOG(WARNING) << "Already reached --stop_at time " << stop_at
                   << " upon starting: winding down immediately";
      RequestEarlyExit(EXIT_SUCCESS);  // => expected outcome
    }
  }
}

// Runs env.for_each_blob on every blob extracted from env.args.
// Returns EXIT_SUCCESS on success, EXIT_FAILURE otherwise.
int ForEachBlob(const Environment &env) {
  auto tmpdir = TemporaryLocalDirPath();
  CreateLocalDirRemovedAtExit(tmpdir);
  std::string tmpfile = std::filesystem::path(tmpdir).append("t");

  for (const auto &arg : env.args) {
    LOG(INFO) << "Running '" << env.for_each_blob << "' on " << arg;
    auto blob_reader = DefaultBlobFileReaderFactory();
    absl::Status open_status = blob_reader->Open(arg);
    if (!open_status.ok()) {
      LOG(INFO) << "Failed to open " << arg << ": " << open_status;
      return EXIT_FAILURE;
    }
    ByteSpan blob;
    while (blob_reader->Read(blob) == absl::OkStatus()) {
      ByteArray bytes;
      bytes.insert(bytes.begin(), blob.data(), blob.end());
      // TODO(kcc): [impl] add a variant of WriteToLocalFile that accepts Span.
      WriteToLocalFile(tmpfile, bytes);
      std::string command_line = absl::StrReplaceAll(
          env.for_each_blob, {{"%P", tmpfile}, {"%H", Hash(bytes)}});
      Command cmd(command_line);
      // TODO(kcc): [as-needed] this creates one process per blob.
      // If this flag gets active use, we may want to define special cases,
      // e.g. if for_each_blob=="cp %P /some/where" we can do it in-process.
      cmd.Execute();
      if (EarlyExitRequested()) return ExitCode();
    }
  }
  return EXIT_SUCCESS;
}

// Loads corpora from work dirs provided in `env.args`, if there are two args
// provided, analyzes differences. If there is one arg provided, reports the
// function coverage. Returns EXIT_SUCCESS on success, EXIT_FAILURE otherwise.
int Analyze(const Environment &env) {
  LOG(INFO) << "Analyze " << absl::StrJoin(env.args, ",");
  CHECK(!env.binary.empty()) << "--binary must be used";
  if (env.args.size() == 1) {
    const CoverageResults coverage_results =
        GetCoverage(env.binary_name, env.binary_hash, env.args[0]);
    WorkDir workdir{env};
    const std::string coverage_report_path =
        workdir.CoverageReportPath(/*annotation=*/"");
    DumpCoverageReport(coverage_results, coverage_report_path);
  } else if (env.args.size() == 2) {
    AnalyzeCorporaToLog(env.binary_name, env.binary_hash, env.args[0],
                        env.args[1]);
  } else {
    LOG(FATAL) << "for now, --analyze supports only 1 or 2 work dirs; got "
               << env.args.size();
  }
  return EXIT_SUCCESS;
}

void SavePCTableToFile(const PCTable &pc_table, std::string_view file_path) {
  WriteToLocalFile(file_path, AsByteSpan(pc_table));
}

BinaryInfo PopulateBinaryInfoAndSavePCsIfNecessary(
    const Environment &env, CentipedeCallbacksFactory &callbacks_factory,
    std::string &pcs_file_path) {
  BinaryInfo binary_info;
  // Some fuzz targets have coverage not based on instrumenting binaries.
  // For those target, we should not populate binary info.
  if (env.populate_binary_info) {
    ScopedCentipedeCallbacks scoped_callbacks(callbacks_factory, env);
    scoped_callbacks.callbacks()->PopulateBinaryInfo(binary_info);
  }
  if (env.save_binary_info) {
    const std::string binary_info_dir = WorkDir{env}.BinaryInfoDirPath();
    CHECK_OK(RemoteMkdir(binary_info_dir));
    LOG(INFO) << "Serializing binary info to: " << binary_info_dir;
    binary_info.Write(binary_info_dir);
  }
  if (binary_info.uses_legacy_trace_pc_instrumentation) {
    pcs_file_path = std::filesystem::path(TemporaryLocalDirPath()) / "pcs";
    SavePCTableToFile(binary_info.pc_table, pcs_file_path);
  }
  if (env.use_pcpair_features) {
    CHECK(!binary_info.pc_table.empty())
        << "--use_pcpair_features requires non-empty pc_table";
  }
  return binary_info;
}

int Fuzz(const Environment &env, const BinaryInfo &binary_info,
         std::string_view pcs_file_path,
         CentipedeCallbacksFactory &callbacks_factory) {
  CoverageLogger coverage_logger(binary_info.pc_table, binary_info.symbols);

  std::vector<Environment> envs(env.num_threads, env);
  std::vector<std::atomic<Stats>> stats_vec(env.num_threads);

  // Start periodic stats dumping and, optionally, logging.
  std::vector<PeriodicAction> stats_reporters;
  stats_reporters.emplace_back(
      [csv_appender = StatsCsvFileAppender{stats_vec, envs}]() mutable {
        csv_appender.ReportCurrStats();
      },
      PeriodicAction::Options{
          .sleep_before_each =
              [](size_t iteration) {
                return absl::Minutes(std::clamp(iteration, 0UL, 10UL));
              },
      });
  if (!envs.front().experiment.empty() || ABSL_VLOG_IS_ON(1)) {
    stats_reporters.emplace_back(
        [logger = StatsLogger{stats_vec, envs}]() mutable {
          logger.ReportCurrStats();
        },
        PeriodicAction::Options{
            .sleep_before_each =
                [](size_t iteration) {
                  return absl::Seconds(std::clamp(iteration, 5UL, 600UL));
                },
        });
  }

  auto fuzzing_worker =
      [&env, pcs_file_path, &callbacks_factory, &binary_info, &coverage_logger](
          Environment &my_env, std::atomic<Stats> &stats, bool create_tmpdir) {
        if (create_tmpdir) CreateLocalDirRemovedAtExit(TemporaryLocalDirPath());
        my_env.UpdateForExperiment();
        // Uses TID, call in this thread.
        my_env.seed = GetRandomSeed(env.seed);
        // Same for all threads.
        my_env.pcs_file_path = pcs_file_path;

        if (env.dry_run) return;

        ScopedCentipedeCallbacks scoped_callbacks(callbacks_factory, my_env);
        Centipede centipede(my_env, *scoped_callbacks.callbacks(), binary_info,
                            coverage_logger, stats);
        centipede.FuzzingLoop();
      };

  if (env.num_threads == 1) {
    // When fuzzing with one thread, run fuzzing loop in the current
    // thread. This is because FuzzTest/Centipede's single-process
    // fuzzing requires the test body, which is invoked by the fuzzing
    // loop, to run in the main thread.
    //
    // Here, the fuzzing worker should not re-create the tmpdir since the path
    // is thread-local and it has been created in the current function.
    fuzzing_worker(envs[0], stats_vec[0], /*create_tmpdir=*/false);
  } else {
    ThreadPool fuzzing_worker_threads{static_cast<int>(env.num_threads)};
    for (size_t thread_idx = 0; thread_idx < env.num_threads; thread_idx++) {
      Environment &my_env = envs[thread_idx];
      my_env.my_shard_index = env.my_shard_index + thread_idx;
      std::atomic<Stats> &my_stats = stats_vec[thread_idx];
      fuzzing_worker_threads.Schedule([&fuzzing_worker, &my_env, &my_stats]() {
        fuzzing_worker(my_env, my_stats, /*create_tmpdir=*/true);
      });
    }  // All `fuzzing_worker_threads` join here.
  }

  for (auto &reporter : stats_reporters) {
    // Nudge one final update and stop the reporting thread.
    reporter.Nudge();
    reporter.Stop();
  }

  if (!env.knobs_file.empty()) PrintRewardValues(stats_vec, std::cerr);

  return ExitCode();
}

struct TestShard {
  int index = 0;
  int total_shards = 1;
};

// https://bazel.build/reference/test-encyclopedia#initial-conditions
absl::Duration GetBazelTestTimeout() {
  const char *test_timeout_env = std::getenv("TEST_TIMEOUT");
  if (test_timeout_env == nullptr) return absl::InfiniteDuration();
  int timeout_s = 0;
  CHECK(absl::SimpleAtoi(test_timeout_env, &timeout_s))
      << "Failed to parse TEST_TIMEOUT: \"" << test_timeout_env << "\"";
  return absl::Seconds(timeout_s);
}

void ReportErrorWhenNotEnoughTimeToRunEverything(absl::Time start_time,
                                                 absl::Duration test_time_limit,
                                                 int executed_tests_in_shard,
                                                 int fuzz_test_count,
                                                 int shard_count) {
  static const absl::Duration bazel_test_timeout = GetBazelTestTimeout();
  constexpr float kTimeoutSafetyFactor = 1.2;
  const auto required_test_time = kTimeoutSafetyFactor * test_time_limit;
  const auto remaining_duration =
      bazel_test_timeout - (absl::Now() - start_time);
  if (required_test_time <= remaining_duration) return;
  std::string error =
      "Cannot fuzz a fuzz test within the given timeout. Please ";
  if (executed_tests_in_shard == 0) {
    // Increasing number of shards won't help.
    const absl::Duration suggested_timeout =
        required_test_time * ((fuzz_test_count - 1) / shard_count + 1);
    absl::StrAppend(&error, "set the `timeout` to ", suggested_timeout,
                    " or reduce the fuzzing time, ");
  } else {
    constexpr int kMaxShardCount = 50;
    const int suggested_shard_count = std::min(
        (fuzz_test_count - 1) / executed_tests_in_shard + 1, kMaxShardCount);
    const int suggested_tests_per_shard =
        (fuzz_test_count - 1) / suggested_shard_count + 1;
    if (suggested_tests_per_shard > executed_tests_in_shard) {
      // We wouldn't be able to execute the suggested number of tests without
      // timeout. This case can only happen if we would in fact need more than
      // `kMaxShardCount` shards, indicating that there are simply too many fuzz
      // tests in a binary.
      CHECK_EQ(suggested_shard_count, kMaxShardCount);
      absl::StrAppend(&error,
                      "split the fuzz tests into several test binaries where "
                      "each binary has at most ",
                      executed_tests_in_shard * kMaxShardCount, "tests ",
                      "with `shard_count` = ", kMaxShardCount, ", ");
    } else {
      // In this case, `suggested_shard_count` must be greater than
      // `shard_count`, otherwise we would have already executed all the tests
      // without a timeout.
      CHECK_GT(suggested_shard_count, shard_count);
      absl::StrAppend(&error, "increase the `shard_count` to ",
                      suggested_shard_count, ", ");
    }
  }
  absl::StrAppend(&error, "to avoid this issue. ");
  absl::StrAppend(&error,
                  "(https://bazel.build/reference/be/"
                  "common-definitions#common-attributes-tests)");
  CHECK(false) << error;
}

TestShard SetUpTestSharding() {
  TestShard test_shard;
  if (const char *test_total_shards_env = std::getenv("TEST_TOTAL_SHARDS");
      test_total_shards_env != nullptr) {
    CHECK(absl::SimpleAtoi(test_total_shards_env, &test_shard.total_shards))
        << "Failed to parse TEST_TOTAL_SHARDS as an integer: \""
        << test_total_shards_env << "\"";
    CHECK_GT(test_shard.total_shards, 0)
        << "TEST_TOTAL_SHARDS must be greater than 0.";
  }
  if (const char *test_shard_index_env = std::getenv("TEST_SHARD_INDEX");
      test_shard_index_env != nullptr) {
    CHECK(absl::SimpleAtoi(test_shard_index_env, &test_shard.index))
        << "Failed to parse TEST_SHARD_INDEX as an integer: \""
        << test_shard_index_env << "\"";
    CHECK(0 <= test_shard.index && test_shard.index < test_shard.total_shards)
        << "TEST_SHARD_INDEX must be in the range [0, "
        << test_shard.total_shards << ").";
  }
  // Update the shard status file to indicate that we support test sharding.
  // It suffices to update the file's modification time, but we clear the
  // contents for simplicity. This is also what the GoogleTest framework does.
  if (const char *test_shard_status_file =
          std::getenv("TEST_SHARD_STATUS_FILE");
      test_shard_status_file != nullptr) {
    ClearLocalFileContents(test_shard_status_file);
  }

  // Unset the environment variables so they don't affect the child processes.
  CHECK_EQ(unsetenv("TEST_TOTAL_SHARDS"), 0)
      << "Failed to unset TEST_TOTAL_SHARDS: " << std::strerror(errno);
  CHECK_EQ(unsetenv("TEST_SHARD_INDEX"), 0)
      << "Failed to unset TEST_SHARD_INDEX: " << std::strerror(errno);
  CHECK_EQ(unsetenv("TEST_SHARD_STATUS_FILE"), 0)
      << "Failed to unset TEST_SHARD_STATUS_FILE: " << std::strerror(errno);

  return test_shard;
}

// Prunes non-reproducible and duplicate crashes and returns the crash metadata
// of the remaining crashes.
absl::flat_hash_set<std::string> PruneOldCrashesAndGetRemainingCrashMetadata(
    const std::filesystem::path &crashing_dir, const Environment &env,
    CentipedeCallbacksFactory &callbacks_factory) {
  const std::vector<std::string> crashing_input_files =
      // The corpus database layout assumes the crash input files are located
      // directly in the crashing subdirectory, so we don't list recursively.
      ValueOrDie(RemoteListFiles(crashing_dir.c_str(), /*recursively=*/false));
  ScopedCentipedeCallbacks scoped_callbacks(callbacks_factory, env);
  BatchResult batch_result;
  absl::flat_hash_set<std::string> remaining_crash_metadata;

  for (const std::string &crashing_input_file : crashing_input_files) {
    ByteArray crashing_input;
    CHECK_OK(RemoteFileGetContents(crashing_input_file, crashing_input));
    const bool is_reproducible = !scoped_callbacks.callbacks()->Execute(
        env.binary, {crashing_input}, batch_result);
    const bool is_duplicate =
        is_reproducible &&
        !remaining_crash_metadata.insert(batch_result.failure_description())
             .second;
    if (!is_reproducible || is_duplicate) {
      CHECK_OK(RemotePathDelete(crashing_input_file, /*recursively=*/false));
    }
  }
  return remaining_crash_metadata;
}

void DeduplicateAndStoreNewCrashes(
    const std::filesystem::path &crashing_dir, const WorkDir &workdir,
    absl::flat_hash_set<std::string> crash_metadata) {
  const std::vector<std::string> new_crashing_input_files =
      // The crash reproducer directory may contain subdirectories with
      // input files that don't individually cause a crash. We ignore those
      // for now and don't list the files recursively.
      ValueOrDie(RemoteListFiles(workdir.CrashReproducerDirPath(),
                                 /*recursively=*/false));
  const std::filesystem::path crash_metadata_dir =
      workdir.CrashMetadataDirPath();

  CHECK_OK(RemoteMkdir(crashing_dir.c_str()));
  for (const std::string &crashing_input_file : new_crashing_input_files) {
    const std::string crashing_input_file_name =
        std::filesystem::path(crashing_input_file).filename();
    const std::string crash_metadata_file =
        crash_metadata_dir / crashing_input_file_name;
    std::string new_crash_metadata;
    CHECK_OK(RemoteFileGetContents(crash_metadata_file, new_crash_metadata));
    const bool is_duplicate = !crash_metadata.insert(new_crash_metadata).second;
    if (is_duplicate) continue;
    CHECK_OK(
        RemotePathRename(crashing_input_file,
                         (crashing_dir / crashing_input_file_name).c_str()));
  }
}

// Seeds the corpus files in `env.workdir` with the previously distilled corpus
// files from `src_dir`.
SeedCorpusConfig GetSeedCorpusConfig(const Environment &env,
                                     std::string_view src_dir) {
  const WorkDir workdir{env};
  return {
      .sources = {SeedCorpusSource{
          .dir_glob = std::string(src_dir),
          .num_recent_dirs = 1,
          // We're using the previously distilled corpus files as seeds.
          .shard_rel_glob =
              std::filesystem::path{
                  workdir.DistilledCorpusFiles().AllShardsGlob()}
                  .filename(),
          .sampled_fraction_or_count = 1.0f,
      }},
      .destination =
          {
              .dir_path = env.workdir,
              // We're seeding the current corpus files.
              .shard_rel_glob =
                  std::filesystem::path{workdir.CorpusFiles().AllShardsGlob()}
                      .filename(),
              .shard_index_digits = WorkDir::kDigitsInShardIndex,
              .num_shards = static_cast<uint32_t>(env.num_threads),
          },
  };
}

// TODO(b/368325638): Add tests for this.
int UpdateCorpusDatabaseForFuzzTests(
    Environment env, const fuzztest::internal::Configuration &fuzztest_config,
    CentipedeCallbacksFactory &callbacks_factory) {
  absl::Time start_time = absl::Now();
  LOG(INFO) << "Starting the update of the corpus database for fuzz tests:"
            << "\nBinary: " << env.binary
            << "\nCorpus database: " << fuzztest_config.corpus_database
            << "\nFuzz tests: "
            << absl::StrJoin(fuzztest_config.fuzz_tests, ", ");

  // Step 1: Preliminary set up of test sharding, binary info, etc.
  const auto [test_shard_index, total_test_shards] = SetUpTestSharding();
  const auto corpus_database_path =
      std::filesystem::path(fuzztest_config.corpus_database) /
      fuzztest_config.binary_identifier;
  const auto stats_root_path =
      fuzztest_config.stats_root.empty()
          ? std::filesystem::path()
          : std::filesystem::path(fuzztest_config.stats_root) /
                fuzztest_config.binary_identifier;
  const auto execution_stamp = [] {
    std::string stamp =
        absl::FormatTime("%Y-%m-%d-%H-%M-%S", absl::Now(), absl::UTCTimeZone());
    return stamp;
  }();
  // the full workdir paths will be formed by appending the fuzz test names to
  // the base workdir path.
  const auto base_workdir_path =
      corpus_database_path / absl::StrFormat("workdir.%03d", test_shard_index);
  // There's no point in saving the binary info to the workdir, since the
  // workdir is deleted at the end.
  env.save_binary_info = false;
  std::string pcs_file_path;
  BinaryInfo binary_info = PopulateBinaryInfoAndSavePCsIfNecessary(
      env, callbacks_factory, pcs_file_path);

  LOG(INFO) << "Test shard index: " << test_shard_index
            << " Total test shards: " << total_test_shards;

  // Step 2: Are we resuming from a previously terminated run?
  // Find the last index of a fuzz test for which we already have a workdir.
  bool is_resuming = false;
  int resuming_fuzztest_idx = 0;
  for (int i = 0; i < fuzztest_config.fuzz_tests.size(); ++i) {
    if (i % total_test_shards != test_shard_index) continue;
    env.workdir = base_workdir_path / fuzztest_config.fuzz_tests[i];
    // Check the existence of the coverage path to not only make sure the
    // workdir exists, but also that it was created for the same binary as in
    // this run.
    if (RemotePathExists(WorkDir{env}.CoverageDirPath())) {
      is_resuming = true;
      resuming_fuzztest_idx = i;
    }
  }

  LOG_IF(INFO, is_resuming) << "Resuming from the fuzz test "
                            << fuzztest_config.fuzz_tests[resuming_fuzztest_idx]
                            << " (index: " << resuming_fuzztest_idx << ")";

  // Step 3: Iterate over the fuzz tests and run them.
  const std::string binary = env.binary;
  for (int i = resuming_fuzztest_idx; i < fuzztest_config.fuzz_tests.size();
       ++i) {
    if (i % total_test_shards != test_shard_index) continue;
    ReportErrorWhenNotEnoughTimeToRunEverything(
        start_time, fuzztest_config.time_limit,
        /*executed_tests_in_shard=*/i / total_test_shards,
        fuzztest_config.fuzz_tests.size(), total_test_shards);
    env.workdir = base_workdir_path / fuzztest_config.fuzz_tests[i];
    if (RemotePathExists(env.workdir) && !is_resuming) {
      // This could be a workdir from a failed run that used a different version
      // of the binary. We delete it so that we don't have to deal with the
      // assumptions under which it is safe to reuse an old workdir.
      CHECK_OK(RemotePathDelete(env.workdir, /*recursively=*/true));
    }
    const WorkDir workdir{env};
    CHECK_OK(RemoteMkdir(
        workdir.CoverageDirPath()));  // Implicitly creates the workdir

    // Seed the fuzzing session with the latest coverage corpus from the
    // previous fuzzing session.
    const std::filesystem::path fuzztest_db_path =
        corpus_database_path / fuzztest_config.fuzz_tests[i];
    const std::filesystem::path coverage_dir = fuzztest_db_path / "coverage";
    if (RemotePathExists(coverage_dir.c_str()) && !is_resuming) {
      CHECK_OK(GenerateSeedCorpusFromConfig(
          GetSeedCorpusConfig(env, coverage_dir.c_str()), env.binary_name,
          env.binary_hash));
    }
    is_resuming = false;

    // TODO: b/338217594 - Call the FuzzTest binary in a flag-agnostic way.
    constexpr std::string_view kFuzzTestFuzzFlag = "--fuzz=";
    env.binary = absl::StrCat(binary, " ", kFuzzTestFuzzFlag,
                              fuzztest_config.fuzz_tests[i]);

    LOG(INFO) << "Fuzzing " << fuzztest_config.fuzz_tests[i]
              << "\n\tTest binary: " << env.binary;

    ClearEarlyExitRequest();
    alarm(absl::ToInt64Seconds(fuzztest_config.GetTimeLimitPerTest()));
    Fuzz(env, binary_info, pcs_file_path, callbacks_factory);
    if (!stats_root_path.empty()) {
      const auto stats_dir = stats_root_path / fuzztest_config.fuzz_tests[i];
      CHECK_OK(RemoteMkdir(stats_dir.c_str()));
      CHECK_OK(RemotePathRename(
          workdir.FuzzingStatsPath(),
          (stats_dir / absl::StrCat("fuzzing_stats_", execution_stamp))
              .c_str()));
    }

    // Distill and store the coverage corpus.
    Distill(env);
    if (RemotePathExists(coverage_dir.c_str())) {
      // In the future, we will store k latest coverage corpora for some k, but
      // for now we only keep the latest one.
      CHECK_OK(RemotePathDelete(coverage_dir.c_str(), /*recursively=*/true));
    }
    CHECK_OK(RemoteMkdir(coverage_dir.c_str()));
    std::vector<std::string> distilled_corpus_files;
    CHECK_OK(RemoteGlobMatch(workdir.DistilledCorpusFiles().AllShardsGlob(),
                             distilled_corpus_files));
    for (const std::string &corpus_file : distilled_corpus_files) {
      const std::string file_name =
          std::filesystem::path(corpus_file).filename();
      CHECK_OK(
          RemotePathRename(corpus_file, (coverage_dir / file_name).c_str()));
    }

    // Deduplicate and update the crashing inputs.
    const std::filesystem::path crashing_dir = fuzztest_db_path / "crashing";
    absl::flat_hash_set<std::string> crash_metadata =
        PruneOldCrashesAndGetRemainingCrashMetadata(crashing_dir, env,
                                                    callbacks_factory);
    DeduplicateAndStoreNewCrashes(crashing_dir, workdir,
                                  std::move(crash_metadata));
  }
  CHECK_OK(RemotePathDelete(base_workdir_path.c_str(), /*recursively=*/true));

  return EXIT_SUCCESS;
}

}  // namespace

int CentipedeMain(const Environment &env,
                  CentipedeCallbacksFactory &callbacks_factory) {
  ClearEarlyExitRequest();
  SetSignalHandlers(env.stop_at);

  if (!env.corpus_to_files.empty()) {
    Centipede::CorpusToFiles(env, env.corpus_to_files);
    return EXIT_SUCCESS;
  }

  if (!env.for_each_blob.empty()) return ForEachBlob(env);

  if (!env.minimize_crash_file_path.empty()) {
    ByteArray crashy_input;
    ReadFromLocalFile(env.minimize_crash_file_path, crashy_input);
    return MinimizeCrash(crashy_input, env, callbacks_factory);
  }

  // Just export the corpus from a local dir and exit.
  if (!env.corpus_from_files.empty()) {
    Centipede::CorpusFromFiles(env, env.corpus_from_files);
    return EXIT_SUCCESS;
  }

  // Export the corpus from a local dir and then fuzz.
  if (!env.corpus_dir.empty()) {
    for (size_t i = 0; i < env.corpus_dir.size(); ++i) {
      const auto &corpus_dir = env.corpus_dir[i];
      if (i > 0 || !env.first_corpus_dir_output_only)
        Centipede::CorpusFromFiles(env, corpus_dir);
    }
  }

  if (env.distill) return Distill(env);

  // Create the local temporary dir once, before creating any threads. The
  // temporary dir must typically exist before `CentipedeCallbacks` can be used.
  const auto tmpdir = TemporaryLocalDirPath();
  CreateLocalDirRemovedAtExit(tmpdir);

  // Enter the update corpus database mode only if we have a binary to invoke
  // and a corpus database to update.
  if (!env.binary.empty()) {
    const std::string serialized_target_config = [&] {
      ScopedCentipedeCallbacks scoped_callbacks(callbacks_factory, env);
      return scoped_callbacks.callbacks()->GetSerializedTargetConfig();
    }();
    if (!serialized_target_config.empty()) {
      const auto target_config = fuzztest::internal::Configuration::Deserialize(
          serialized_target_config);
      CHECK_OK(target_config.status())
          << "Failed to deserialize target configuration";
      if (!target_config->corpus_database.empty()) {
        const auto time_limit_per_test = target_config->GetTimeLimitPerTest();
        CHECK(time_limit_per_test < absl::InfiniteDuration())
            << "Updating corpus database requires specifying time limit per "
               "fuzz test.";
        CHECK(time_limit_per_test >= absl::Seconds(1))
            << "Time limit per fuzz test must be at least 1 second.";
        return UpdateCorpusDatabaseForFuzzTests(env, *target_config,
                                                callbacks_factory);
      }
    } else if (std::getenv("CENTIPEDE_NO_FUZZ_IF_NO_CONFIG") != nullptr) {
      // Target config is empty when the shard does not contain any fuzz tests.
      LOG(INFO) << "No fuzz test found!";
      return EXIT_SUCCESS;
    }
  }

  // Create the remote coverage dirs once, before creating any threads.
  const auto coverage_dir = WorkDir{env}.CoverageDirPath();
  CHECK_OK(RemoteMkdir(coverage_dir));
  LOG(INFO) << "Coverage dir: " << coverage_dir
            << "; temporary dir: " << tmpdir;

  std::string pcs_file_path;
  BinaryInfo binary_info = PopulateBinaryInfoAndSavePCsIfNecessary(
      env, callbacks_factory, pcs_file_path);

  if (env.analyze) return Analyze(env);

  return Fuzz(env, binary_info, pcs_file_path, callbacks_factory);
}

}  // namespace centipede
