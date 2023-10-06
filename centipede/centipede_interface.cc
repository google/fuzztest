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
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>  // NOLINT(build/c++11)
#include <vector>

#include "absl/base/optimization.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./centipede/analyze_corpora.h"
#include "./centipede/binary_info.h"
#include "./centipede/blob_file.h"
#include "./centipede/centipede.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/command.h"
#include "./centipede/corpus.h"
#include "./centipede/coverage.h"
#include "./centipede/defs.h"
#include "./centipede/distill.h"
#include "./centipede/environment.h"
#include "./centipede/feature.h"
#include "./centipede/logging.h"  // IWYU pragma: keep
#include "./centipede/minimize_crash.h"
#include "./centipede/pc_info.h"
#include "./centipede/remote_file.h"
#include "./centipede/shard_reader.h"
#include "./centipede/stats.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"

namespace centipede {

namespace {

// Sets signal handler for SIGINT.
void SetSignalHandlers(absl::Time stop_at) {
  for (int signum : {SIGINT, SIGALRM}) {
    struct sigaction sigact = {};
    // Reset the handler to SIG_DFL upon entry into our custom handler.
    sigact.sa_flags = SA_RESETHAND;
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
    absl::Span<uint8_t> blob;
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

// Runs in a dedicated thread, periodically calls PrintExperimentStats
// on `stats_vec` and `envs`.
// Stops when `continue_running` becomes false.
// Exits immediately if --experiment flag is not used.
void ReportStatsThread(const std::atomic<bool> &continue_running,
                       const std::vector<Stats> &stats_vec,
                       const std::vector<Environment> &envs) {
  CHECK(!envs.empty());

  std::vector<std::unique_ptr<StatsReporter>> reporters;
  reporters.emplace_back(
      std::make_unique<StatsCsvFileAppender>(stats_vec, envs));
  if (!envs.front().experiment.empty() || VLOG_IS_ON(1)) {
    reporters.emplace_back(std::make_unique<StatsLogger>(stats_vec, envs));
  }

  // TODO(ussuri): Use constant time increments for CSV generation?
  for (int i = 0; continue_running; ++i) {
    // Sleep at least a few seconds, and at most 600.
    int seconds_to_sleep = std::clamp(i, 5, 600);
    // Sleep(1) in a loop so that we check continue_running once a second.
    while (--seconds_to_sleep && continue_running) {
      absl::SleepFor(absl::Seconds(1));
    }
    for (auto &reporter : reporters) {
      reporter->ReportCurrStats();
    }
  }
}

// Loads corpora from work dirs provided in `env.args`, analyzes differences.
// Returns EXIT_SUCCESS on success, EXIT_FAILURE otherwise.
int Analyze(const Environment &env) {
  LOG(INFO) << "Analyze " << absl::StrJoin(env.args, ",");
  CHECK_EQ(env.args.size(), 2) << "for now, Analyze supports only 2 work dirs";
  CHECK(!env.binary.empty()) << "--binary must be used";
  std::vector<std::vector<CorpusRecord>> corpora;
  AnalyzeCorporaToLog(env.binary_name, env.binary_hash, env.args[0],
                      env.args[1]);
  return EXIT_SUCCESS;
}

void SavePCTableToFile(const PCTable &pc_table, std::string_view file_path) {
  ByteSpan bytes = {reinterpret_cast<const uint8_t *>(pc_table.data()),
                    pc_table.size() * sizeof(pc_table[0])};
  WriteToLocalFile(file_path, bytes);
}

}  // namespace

int CentipedeMain(const Environment &env,
                  CentipedeCallbacksFactory &callbacks_factory) {
  SetSignalHandlers(env.stop_at);

  if (!env.save_corpus_to_local_dir.empty()) {
    Centipede::SaveCorpusToLocalDir(env, env.save_corpus_to_local_dir);
    return EXIT_SUCCESS;
  }

  if (!env.for_each_blob.empty()) return ForEachBlob(env);

  if (!env.minimize_crash_file_path.empty()) {
    ByteArray crashy_input;
    ReadFromLocalFile(env.minimize_crash_file_path, crashy_input);
    return MinimizeCrash(crashy_input, env, callbacks_factory);
  }

  // Just export the corpus from a local dir and exit.
  if (!env.export_corpus_from_local_dir.empty()) {
    Centipede::ExportCorpusFromLocalDir(env, env.export_corpus_from_local_dir);
    return EXIT_SUCCESS;
  }

  // Export the corpus from a local dir and then fuzz.
  if (!env.corpus_dir.empty()) {
    for (const auto &corpus_dir : env.corpus_dir) {
      Centipede::ExportCorpusFromLocalDir(env, corpus_dir);
    }
  }

  if (env.distill) return Distill(env);

  // Create the local temporary dir and remote coverage dirs once, before
  // creating any threads.
  const auto coverage_dir = WorkDir{env}.CoverageDirPath();
  RemoteMkdir(coverage_dir);
  const auto tmpdir = TemporaryLocalDirPath();
  CreateLocalDirRemovedAtExit(tmpdir);
  LOG(INFO) << "Coverage dir: " << coverage_dir
            << "; temporary dir: " << tmpdir;

  BinaryInfo binary_info;
  // Some fuzz targets have coverage not based on instrumenting binaries.
  // For those target, we should not populate binary info.
  if (env.populate_binary_info) {
    ScopedCentipedeCallbacks scoped_callbacks(callbacks_factory, env);
    scoped_callbacks.callbacks()->PopulateBinaryInfo(binary_info);
  }

  if (env.save_binary_info) {
    const std::string binary_info_dir = WorkDir{env}.BinaryInfoDirPath();
    RemoteMkdir(binary_info_dir);
    LOG(INFO) << "Serializing binary info to: " << binary_info_dir;
    binary_info.Write(binary_info_dir);
  }

  std::string pcs_file_path;
  if (binary_info.uses_legacy_trace_pc_instrumentation) {
    pcs_file_path = std::filesystem::path(tmpdir).append("pcs");
    SavePCTableToFile(binary_info.pc_table, pcs_file_path);
  }

  if (env.analyze) return Analyze(env);

  if (env.use_pcpair_features) {
    CHECK(!binary_info.pc_table.empty())
        << "--use_pcpair_features requires non-empty pc_table";
  }
  CoverageLogger coverage_logger(binary_info.pc_table, binary_info.symbols);

  auto thread_callback = [&](Environment &my_env, Stats &stats) {
    CreateLocalDirRemovedAtExit(TemporaryLocalDirPath());  // creates temp dir.
    my_env.seed = GetRandomSeed(env.seed);  // uses TID, call in this thread.
    my_env.pcs_file_path = pcs_file_path;   // same for all threads.

    if (env.dry_run) return;

    ScopedCentipedeCallbacks scoped_callbacks(callbacks_factory, my_env);
    Centipede centipede(my_env, *scoped_callbacks.callbacks(), binary_info,
                        coverage_logger, stats);
    centipede.FuzzingLoop();
  };

  std::vector<Environment> envs(env.num_threads, env);
  std::vector<Stats> stats_vec(env.num_threads);
  std::vector<std::thread> threads(env.num_threads);
  std::atomic<bool> stats_thread_continue_running(true);

  // Create threads.
  for (size_t thread_idx = 0; thread_idx < env.num_threads; thread_idx++) {
    Environment &my_env = envs[thread_idx];
    my_env.my_shard_index = env.my_shard_index + thread_idx;
    my_env.UpdateForExperiment();
    threads[thread_idx] = std::thread(thread_callback, std::ref(my_env),
                                      std::ref(stats_vec[thread_idx]));
  }

  std::thread stats_thread(ReportStatsThread,
                           std::ref(stats_thread_continue_running),
                           std::ref(stats_vec), std::ref(envs));

  // Join threads.
  for (size_t thread_idx = 0; thread_idx < env.num_threads; thread_idx++) {
    threads[thread_idx].join();
  }
  stats_thread_continue_running = false;
  stats_thread.join();

  if (!env.knobs_file.empty()) PrintRewardValues(stats_vec, std::cerr);

  return ExitCode();
}

}  // namespace centipede
