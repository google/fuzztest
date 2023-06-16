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

#include "./centipede/environment.h"

#include <charconv>
#include <cmath>
#include <cstddef>
#include <filesystem>  // NOLINT
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "./centipede/logging.h"
#include "./centipede/remote_file.h"
#include "./centipede/util.h"

// TODO(kcc): document usage of standalone binaries and how to use @@ wildcard.
// If the "binary" contains @@, it means the binary can only accept inputs
// from the command line, and only one input per process.
// @@ will be replaced with a path to file with the input.
// @@ is chosen to follow the AFL command line syntax.
// TODO(kcc): rename --binary to --command (same for --extra_binaries),
// while remaining backward compatible.
ABSL_FLAG(std::string, binary, "", "The target binary.");
ABSL_FLAG(std::string, coverage_binary, "",
          "The actual binary from which coverage is collected - if different "
          "from --binary.");
ABSL_FLAG(std::string, clang_coverage_binary, "",
          "A clang source-based code coverage binary used to produce "
          "human-readable reports. Do not add this binary to extra_binaries. "
          "You must have llvm-cov and llvm-profdata in your path to generate "
          "the reports. --workdir in turn must be local in order for this "
          "functionality to work. See "
          "https://clang.llvm.org/docs/SourceBasedCodeCoverage.html");
ABSL_FLAG(std::string, extra_binaries, "",
          "A comma-separated list of extra target binaries. These binaries are "
          "fed the same inputs as the main binary, but the coverage feedback "
          "from them is not collected. Use this e.g. to run the target under "
          "sanitizers.");
ABSL_FLAG(std::string, workdir, "", "The working directory.");
ABSL_FLAG(std::string, merge_from, "",
          "Another working directory to merge the corpus from. Inputs from "
          "--merge_from will be added to --workdir if the add new features.");
ABSL_FLAG(size_t, num_runs, std::numeric_limits<size_t>::max(),
          "Number of inputs to run per shard (see --total_shards).");
ABSL_FLAG(size_t, seed, 0,
          "A seed for the random number generator. If 0, some other random "
          "number is used as seed.");
ABSL_FLAG(size_t, total_shards, 1, "Number of shards.");
ABSL_FLAG(size_t, first_shard_index, 0,
          "Index of the first shard, [0, --total_shards - --num_threads].");
ABSL_FLAG(size_t, num_threads, 1,
          "Number of threads to execute in one process. i-th thread, where i "
          "is in [0, --num_threads), will work on shard "
          "(--first_shard_index + i).");
ABSL_FLAG(size_t, j, 0,
          "If not 0, --j=N is a shorthand for "
          "--num_threads=N --total_shards=N --first_shard_index=0. "
          "Overrides values of these flags if they are also used.");
ABSL_FLAG(size_t, max_len, 4096, "Max length of mutants. Passed to mutator.");
ABSL_FLAG(size_t, batch_size, 1000,
          "The number of inputs given to the target at one time. Batches of "
          "more than 1 input are used to amortize the process start-up cost.")
    .OnUpdate([]() {
      QCHECK_GT(absl::GetFlag(FLAGS_batch_size), 0)
          << "--" << FLAGS_batch_size.Name() << " must be non-zero";
    });
ABSL_FLAG(size_t, mutate_batch_size, 2,
          "Mutate this many inputs to produce batch_size mutants");
ABSL_FLAG(bool, use_legacy_default_mutator, false,
          "When set, use the legacy ByteArrayMutator as the default mutator. "
          "Otherwise, the FuzzTest domain based mutator will be used.");
ABSL_FLAG(size_t, load_other_shard_frequency, 10,
          "Load a random other shard after processing this many batches. Use 0 "
          "to disable loading other shards.  For now, choose the value of this "
          "flag so that shard loads  happen at most once in a few minutes. In "
          "future we may be able to find the suitable value automatically.");
// TODO(b/262798184): Remove once the bug is fixed.
ABSL_FLAG(bool, serialize_shard_loads, false,
          "When this flag is on, shard loading is serialized. "
          " Useful to avoid excessive RAM consumption when loading more"
          " that one shard at a time. Currently, loading a single large shard"
          " may create too many temporary heap allocations. "
          " This means, if we load many large shards concurrently,"
          " we may run out or RAM.");
ABSL_FLAG(size_t, prune_frequency, 100,
          "Prune the corpus every time after this many inputs were added. If "
          "zero, pruning is disabled. Pruning removes redundant inputs from "
          "the corpus, e.g. inputs that have only \"frequent\", i.e. "
          "uninteresting features. When the corpus gets larger than "
          "--max_corpus_size, some random elements may also be removed.");
ABSL_FLAG(size_t, address_space_limit_mb, 8192,
          "If not zero, instructs the target to set setrlimit(RLIMIT_AS) to "
          "this number of megabytes. Some targets (e.g. if built with ASAN, "
          "which can't run with RLIMIT_AS) may choose to ignore this flag. See "
          "also --rss_limit_mb.");
ABSL_FLAG(size_t, rss_limit_mb, 4096,
          "If not zero, instructs the target to fail if RSS goes over this "
          "number of megabytes and report an OOM. See also "
          "--address_space_limit_mb. These two flags have somewhat different "
          "meaning. --address_space_limit_mb does not allow the process to "
          "grow the used address space beyond the limit. --rss_limit_mb runs a "
          "background thread that monitors max RSS and also checks max RSS "
          "after executing every input, so it may detect OOM late. However "
          "--rss_limit_mb allows Centipede to *report* an OOM condition in "
          "most cases, while --address_space_limit_mb will cause a crash that "
          "may be hard to attribute to OOM.");
ABSL_FLAG(size_t, timeout_per_input, 60,
          "If not zero, the timeout in seconds for a single input. If an input "
          "runs longer than this, the runner process will abort. Support may "
          "vary depending on the runner.");
ABSL_FLAG(size_t, timeout, 60,
          "An alias for --timeout_per_input. If both are passed, the last of "
          "the two wins.")
    .OnUpdate([]() {
      absl::SetFlag(&FLAGS_timeout_per_input, absl::GetFlag(FLAGS_timeout));
    });
ABSL_FLAG(size_t, timeout_per_batch, 0,
          "If not zero, the collective timeout budget in seconds for a single "
          "batch of inputs. Each input in a batch still has up to "
          "--timeout_per_input seconds to finish, but the entire batch must "
          "finish within --timeout_per_batch seconds. The default is computed "
          "as a function of --timeout_per_input * --batch_size. Support may "
          "vary depending on the runner.");
ABSL_FLAG(absl::Time, stop_at, absl::InfiniteFuture(),
          "Stop fuzzing in all shards (--total_shards) at approximately this "
          "time in ISO-8601/RFC-3339 format, e.g. 2023-04-06T23:35:02Z. "
          "If a given shard is still running at that time, it will gracefully "
          "wind down by letting the current batch of inputs to finish and then "
          "exiting. A special value 'infinite-future' (the default) is "
          "supported. Tip: `date` is useful for conversion of mostly free "
          "format human readable date/time strings, e.g. "
          "--stop_at=$(date --date='next Monday 6pm' --utc --iso-8601=seconds) "
          ". Also see --stop_after. If both are specified, the last one wins.");
ABSL_FLAG(absl::Duration, stop_after, absl::InfiniteDuration(),
          "Equivalent to setting --stop_at to the current date/time + this "
          "duration. If both flags are specified, the last one wins.")
    .OnUpdate([]() {
      absl::SetFlag(  //
          &FLAGS_stop_at, absl::Now() + absl::GetFlag(FLAGS_stop_after));
    });
ABSL_FLAG(bool, fork_server, true,
          "If true (default) tries to execute the target(s) via the fork "
          "server, if supported by the target(s). Prepend the binary path with "
          "'%f' to disable the fork server. --fork_server applies to binaries "
          "passed via these flags: --binary, --extra_binaries, "
          "--input_filter.");
ABSL_FLAG(bool, full_sync, false,
          "Perform a full corpus sync on startup. If true, feature sets and "
          "corpora are read from all shards before fuzzing. This way fuzzing "
          "starts with a full knowledge of the current state and will avoid "
          "adding duplicating inputs. This however is very expensive when the "
          "number of shards is very large.");
ABSL_FLAG(bool, use_corpus_weights, true,
          "If true, use weighted distribution when choosing the corpus element "
          "to mutate. This flag is mostly for Centipede developers.");
ABSL_FLAG(bool, use_coverage_frontier, false,
          "If true, use coverage frontier when choosing the corpus element to "
          "mutate. This flag is mostly for Centipede developers.");
ABSL_FLAG(size_t, max_corpus_size, 100000,
          "Indicates the number of inputs in the in-memory corpus after which"
          "more aggressive pruning will be applied.");
ABSL_FLAG(size_t, crossover_level, 50,
          "Defines how much crossover is used during mutations. 0 means no "
          "crossover, 100 means the most aggressive crossover. See "
          "https://en.wikipedia.org/wiki/Crossover_(genetic_algorithm).");
ABSL_FLAG(bool, use_pc_features, true,
          "When available from instrumentation, use features derived from "
          "PCs.");
ABSL_FLAG(bool, use_cmp_features, true,
          "When available from instrumentation, use features derived from "
          "instrumentation of CMP instructions.");
ABSL_FLAG(size_t, callstack_level, 0,
          "When available from instrumentation, use features derived from "
          "observing the function call stacks. 0 means no callstack features."
          "Values between 1 and 100 define how aggressively to use the "
          "callstacks. Level N roughly corresponds to N call frames.")
    .OnUpdate([]() {
      QCHECK_LE(absl::GetFlag(FLAGS_callstack_level), 100)
          << "--" << FLAGS_callstack_level.Name() << " must be in [0,100]";
    });
ABSL_FLAG(bool, use_auto_dictionary, true,
          "If true, use automatically-generated dictionary derived from "
          "intercepting comparison instructions, memcmp, and similar.");
ABSL_FLAG(size_t, path_level, 0,  // Not ready for wide usage.
          "When available from instrumentation, use features derived from "
          "bounded execution paths. Be careful, may cause exponential feature "
          "explosion. 0 means no path features. Values between 1 and 100 "
          "define how aggressively to use the paths.")
    .OnUpdate([]() {
      QCHECK_LE(absl::GetFlag(FLAGS_path_level), 100)
          << "--" << FLAGS_path_level.Name() << " must be in [0,100]";
    });
ABSL_FLAG(bool, use_dataflow_features, true,
          "When available from instrumentation, use features derived from "
          "data flows.");
ABSL_FLAG(bool, use_counter_features, false,
          "When available from instrumentation, use features derived from "
          "counting the number of occurrences of a given PC. When enabled, "
          "supersedes --use_pc_features.");
ABSL_FLAG(bool, use_pcpair_features, false,
          "If true, PC pairs are used as additional synthetic features. "
          "Experimental, use with care - it may explode the corpus.");
ABSL_FLAG(size_t, feature_frequency_threshold, 100,
          "Internal flag. When a given feature is present in the corpus this "
          "many times Centipede will stop recording it for future corpus "
          "elements. Larger values will use more RAM but may improve corpus "
          "weights. Valid values are 1 - 255.");
ABSL_FLAG(bool, require_pc_table, true,
          "If true, Centipede will exit if the --pc_table is not found.");
ABSL_FLAG(int, telemetry_frequency, 0,
          "Dumping frequency for intermediate telemetry files, i.e. coverage "
          "report (workdir/coverage-report-BINARY.*.txt), corpus stats "
          "(workdir/corpus-stats-*.json), etc. Positive value N means dump "
          "every N batches. Negative N means start dumping after 2^N processed "
          "batches with exponential 2x back-off (e.g. for "
          "--telemetry_frequency=-5, dump on batches 32, 64, 128,...). Zero "
          "means no telemetry. Note that the before-fuzzing and after-fuzzing "
          "telemetry are always dumped.");
ABSL_FLAG(bool, print_runner_log, false,
          "If true, runner logs are printed after every batch. Note that "
          "crash logs are always printed regardless of this flag's value.");
ABSL_FLAG(std::string, knobs_file, "",
          "If not empty, knobs will be read from this (possibly remote) file."
          " The feature is experimental, not yet fully functional.");
ABSL_FLAG(std::string, save_corpus_to_local_dir, "",
          "Save the remote corpus from working to the given directory, one "
          "file per corpus.");
ABSL_FLAG(std::string, export_corpus_from_local_dir, "",
          "Export a corpus from a local directory with one file per input into "
          "the sharded remote corpus in workdir. Not recursive.");
ABSL_FLAG(std::string, corpus_dir, "",
          "Comma-separated list of paths to local corpus dirs, with one file "
          "per input. At startup, the files are exported into the corpus in "
          "--workdir. While fuzzing, the new corpus elements are written to "
          "the first dir. This makes it more convenient to interop with "
          "libFuzzer corpora.");
ABSL_FLAG(std::string, symbolizer_path, "llvm-symbolizer",
          "Path to the symbolizer tool. By default, we use llvm-symbolizer "
          "and assume it is in PATH.");
ABSL_FLAG(std::string, objdump_path, "objdump",
          "Path to the objdump tool. By default, we use the system objdump "
          "and assume it is in PATH.");
ABSL_FLAG(std::string, runner_dl_path_suffix, "",
          "If non-empty, this flag is passed to the Centipede runner. "
          "It tells the runner that this dynamic library is instrumented "
          "while the main binary is not. "
          "The value could be the full path, like '/path/to/my.so' "
          "or a suffix, like '/my.so' or 'my.so'."
          "This flag is experimental and may be removed in future");
ABSL_FLAG(size_t, distill_shards, 0,
          "The first --distill_shards will write the distilled corpus to "
          "workdir/distilled-BINARY.SHARD files. Also, if --corpus_dir is "
          "specified, the distilled corpus shards will be duplicated to its "
          "first element. Note that every shard will produce its own variant "
          "of distilled corpus thanks to random loading order. Distillation "
          "will work properly only if all shards already have their feature "
          "files computed.");
ABSL_FLAG(size_t, log_features_shards, 0,
          "The first --log_features_shards shards will log newly observed "
          "features as symbols. In most cases you don't need this to be >= 2.");
ABSL_FLAG(bool, exit_on_crash, false,
          "If true, Centipede will exit on the first crash of the target.");
ABSL_FLAG(size_t, num_crash_reports, 5, "report this many crashes per shard.");
ABSL_FLAG(std::string, minimize_crash, "",
          "If non-empty, a path to an input file that triggers a crash."
          " Centipede will run the minimization loop and store smaller crash-y"
          " inputs in workdir/crashes/."
          " --num_runs and --num_threads apply. "
          " Assumes local workdir.");
ABSL_FLAG(std::string, input_filter, "",
          "Path to a tool that filters bad inputs. The tool is invoked as "
          "`input_filter INPUT_FILE` and should return 0 if the input is good "
          "and non-0 otherwise. Ignored if empty. The --input_filter is "
          "invoked only for inputs that are considered for addition to the "
          "corpus.");
ABSL_FLAG(std::string, for_each_blob, "",
          "If non-empty, extracts individual blobs from the files given as "
          "arguments, copies each blob to a temporary file, and applies this "
          "command to that temporary file. %P is replaced with the temporary "
          "file's path and %H is replaced with the blob's hash. Example:\n"
          "$ centipede --for_each_blob='ls -l  %P && echo %H' corpus.0");
ABSL_FLAG(std::string, experiment, "",
          "A colon-separated list of values, each of which is a flag followed "
          "by = and a comma-separated list of values. Example: "
          "'foo=1,2,3:bar=10,20'. When non-empty, this flag is used to run an "
          "A/B[/C/D...] experiment: different threads will set different "
          "values of 'foo' and 'bar' and will run independent fuzzing "
          "sessions. If more than one flag is given, all flag combinations are "
          "tested. In example above: '--foo=1 --bar=10' ... "
          "'--foo=3 --bar=20'. The number of threads should be multiple of the "
          "number of flag combinations.");
ABSL_FLAG(bool, analyze, false,
          "If set, Centipede will read the corpora from the work dirs provided"
          " as argv and analyze differences between those corpora."
          " Used by the Centipede developers to improve the engine. "
          " TODO(kcc) implement. ");
ABSL_FLAG(std::string, dictionary, "",
          "A comma-separated list of paths to dictionary files. The dictionary "
          "file is either in AFL/libFuzzer plain text format or in the binary "
          "Centipede corpus file format. The flag is interpreted by "
          "CentipedeCallbacks so its meaning may be different in custom "
          "implementations of CentipedeCallbacks.");
ABSL_FLAG(std::string, function_filter, "",
          "A comma-separated list of functions that fuzzing needs to focus on. "
          "If this list is non-empty, the fuzzer will mutate only those inputs "
          "that trigger code in one of these functions.");
ABSL_FLAG(size_t, shmem_size_mb, 1024,
          "Size of the shared memory regions used to communicate between the "
          "ending and the runner.");
ABSL_FLAG(bool, dry_run, false,
          "Initializes as much of Centipede as possible without actually "
          "running any fuzzing. Useful to validate the rest of the command "
          "line, verify existence of all the input directories and files, "
          "etc. Also useful in combination with --save_config or "
          "--update_config to stop execution immediately after writing the "
          "(updated) config file.");

namespace centipede {

namespace {

// If the passed `timeout_per_batch` is 0, computes its value as a function of
// `timeout_per_input` and `batch_size` and returns it. Otherwise, just returns
// the `timeout_per_batch`.
size_t ComputeTimeoutPerBatch(  //
    size_t timeout_per_batch, size_t timeout_per_input, size_t batch_size) {
  if (timeout_per_batch == 0) {
    CHECK_GT(batch_size, 0);
    // NOTE: If `timeout_per_input` == 0, leave `timeout_per_batch` at 0 too:
    // the implementation interprets both as "no limit".
    if (timeout_per_input != 0) {
      // TODO(ussuri): The formula here is an unscientific heuristic conjured
      //  up for CPU instruction fuzzing. `timeout_per_input` is interpreted as
      //  the long tail of the input runtime distribution of yet-unknown nature.
      //  It might be the exponential, log-normal distribution or similar, and
      //  the distribution of the total time per batch could be modeled by the
      //  gamma distribution. Work out the math later. Right now, this naive
      //  formula gives ~18 min per batch with the input flags' defaults (this
      //  has worked in test runs so far).
      constexpr double kScale = 12;
      const double estimated_mean_time_per_input =
          std::max(timeout_per_input / kScale, 1.0);
      timeout_per_batch =
          std::ceil(std::log(estimated_mean_time_per_input + 1.0) * batch_size);
    }
    VLOG(1) << "--" << FLAGS_timeout_per_batch.Name()
            << " not set on command line: auto-computed " << timeout_per_batch
            << " sec (see --help for details)";
  }
  return timeout_per_batch;
}

}  // namespace

Environment::Environment(const std::vector<std::string> &argv)
    : binary(absl::GetFlag(FLAGS_binary)),
      coverage_binary(
          absl::GetFlag(FLAGS_coverage_binary).empty()
              ? (binary.empty() ? "" : *absl::StrSplit(binary, ' ').begin())
              : absl::GetFlag(FLAGS_coverage_binary)),
      clang_coverage_binary(absl::GetFlag(FLAGS_clang_coverage_binary)),
      extra_binaries(absl::StrSplit(absl::GetFlag(FLAGS_extra_binaries), ',',
                                    absl::SkipEmpty{})),
      workdir(absl::GetFlag(FLAGS_workdir)),
      merge_from(absl::GetFlag(FLAGS_merge_from)),
      num_runs(absl::GetFlag(FLAGS_num_runs)),
      total_shards(absl::GetFlag(FLAGS_total_shards)),
      my_shard_index(absl::GetFlag(FLAGS_first_shard_index)),
      num_threads(absl::GetFlag(FLAGS_num_threads)),
      max_len(absl::GetFlag(FLAGS_max_len)),
      batch_size(absl::GetFlag(FLAGS_batch_size)),
      mutate_batch_size(absl::GetFlag(FLAGS_mutate_batch_size)),
      use_legacy_default_mutator(
          absl::GetFlag(FLAGS_use_legacy_default_mutator)),
      load_other_shard_frequency(
          absl::GetFlag(FLAGS_load_other_shard_frequency)),
      serialize_shard_loads(absl::GetFlag(FLAGS_serialize_shard_loads)),
      seed(absl::GetFlag(FLAGS_seed)),
      prune_frequency(absl::GetFlag(FLAGS_prune_frequency)),
      address_space_limit_mb(absl::GetFlag(FLAGS_address_space_limit_mb)),
      rss_limit_mb(absl::GetFlag(FLAGS_rss_limit_mb)),
      timeout_per_input(absl::GetFlag(FLAGS_timeout_per_input)),
      timeout_per_batch(ComputeTimeoutPerBatch(    //
          absl::GetFlag(FLAGS_timeout_per_batch),  //
          absl::GetFlag(FLAGS_timeout_per_input),  //
          absl::GetFlag(FLAGS_batch_size))),
      stop_at(absl::GetFlag(FLAGS_stop_at)),
      fork_server(absl::GetFlag(FLAGS_fork_server)),
      full_sync(absl::GetFlag(FLAGS_full_sync)),
      use_corpus_weights(absl::GetFlag(FLAGS_use_corpus_weights)),
      use_coverage_frontier(absl::GetFlag(FLAGS_use_coverage_frontier)),
      max_corpus_size(absl::GetFlag(FLAGS_max_corpus_size)),
      crossover_level(absl::GetFlag(FLAGS_crossover_level)),
      use_pc_features(absl::GetFlag(FLAGS_use_pc_features)),
      path_level(absl::GetFlag(FLAGS_path_level)),
      use_cmp_features(absl::GetFlag(FLAGS_use_cmp_features)),
      callstack_level(absl::GetFlag(FLAGS_callstack_level)),
      use_auto_dictionary(absl::GetFlag(FLAGS_use_auto_dictionary)),
      use_dataflow_features(absl::GetFlag(FLAGS_use_dataflow_features)),
      use_counter_features(absl::GetFlag(FLAGS_use_counter_features)),
      use_pcpair_features(absl::GetFlag(FLAGS_use_pcpair_features)),
      feature_frequency_threshold(
          absl::GetFlag(FLAGS_feature_frequency_threshold)),
      require_pc_table(absl::GetFlag(FLAGS_require_pc_table)),
      telemetry_frequency(absl::GetFlag(FLAGS_telemetry_frequency)),
      print_runner_log(absl::GetFlag(FLAGS_print_runner_log)),
      distill_shards(absl::GetFlag(FLAGS_distill_shards)),
      log_features_shards(absl::GetFlag(FLAGS_log_features_shards)),
      knobs_file(absl::GetFlag(FLAGS_knobs_file)),
      save_corpus_to_local_dir(absl::GetFlag(FLAGS_save_corpus_to_local_dir)),
      export_corpus_from_local_dir(
          absl::GetFlag(FLAGS_export_corpus_from_local_dir)),
      corpus_dir(absl::StrSplit(absl::GetFlag(FLAGS_corpus_dir), ',',
                                absl::SkipEmpty{})),
      symbolizer_path(absl::GetFlag(FLAGS_symbolizer_path)),
      objdump_path(absl::GetFlag(FLAGS_objdump_path)),
      runner_dl_path_suffix(absl::GetFlag(FLAGS_runner_dl_path_suffix)),
      input_filter(absl::GetFlag(FLAGS_input_filter)),
      dictionary(absl::StrSplit(absl::GetFlag(FLAGS_dictionary), ',',
                                absl::SkipEmpty{})),
      function_filter(absl::GetFlag(FLAGS_function_filter)),
      for_each_blob(absl::GetFlag(FLAGS_for_each_blob)),
      experiment(absl::GetFlag(FLAGS_experiment)),
      analyze(absl::GetFlag(FLAGS_analyze)),
      exit_on_crash(absl::GetFlag(FLAGS_exit_on_crash)),
      max_num_crash_reports(absl::GetFlag(FLAGS_num_crash_reports)),
      minimize_crash_file_path(absl::GetFlag(FLAGS_minimize_crash)),
      shmem_size_mb(absl::GetFlag(FLAGS_shmem_size_mb)),
      dry_run(absl::GetFlag(FLAGS_dry_run)),
      cmd(binary),
      binary_name(std::filesystem::path(coverage_binary).filename().string()),
      binary_hash(HashOfFileContents(coverage_binary)) {
  if (size_t j = absl::GetFlag(FLAGS_j)) {
    total_shards = j;
    num_threads = j;
    my_shard_index = 0;
  }
  CHECK_GE(total_shards, 1);
  CHECK_GE(batch_size, 1);
  CHECK_GE(num_threads, 1);
  CHECK_LE(num_threads, total_shards);
  CHECK_LE(my_shard_index + num_threads, total_shards)
      << VV(my_shard_index) << VV(num_threads);
  if (!argv.empty()) {
    exec_name = argv[0];
    for (size_t i = 1; i < argv.size(); ++i) {
      args.emplace_back(argv[i]);
    }
  }

  if (!clang_coverage_binary.empty())
    extra_binaries.push_back(clang_coverage_binary);

  if (absl::StrContains(binary, "@@")) {
    LOG(INFO) << "@@ detected; running in standalone mode with batch_size=1";
    has_input_wildcards = true;
    batch_size = 1;
    // TODO(kcc): do we need to check if extra_binaries have @@?
  }

  ReadKnobsFileIfSpecified();
}

namespace {

// Max number of decimal digits in a shard index given `total_shards`. Used to
// pad indices with 0's in output file names so the names are sorted by index.
inline constexpr int kDigitsInShardIndex = 6;

// If `annotation` is empty, returns an empty string. Otherwise, verifies that
// it does not start with a dot and returns it with a dot prepended.
std::string NormalizeAnnotation(std::string_view annotation) {
  std::string ret;
  if (!annotation.empty()) {
    CHECK_NE(annotation.front(), '.');
    ret = absl::StrCat(".", annotation);
  }
  return ret;
}

}  // namespace

std::string Environment::MakeCoverageDirPath() const {
  return std::filesystem::path(workdir).append(
      absl::StrCat(binary_name, "-", binary_hash));
}

std::string Environment::MakeCrashReproducerDirPath() const {
  return std::filesystem::path(workdir).append("crashes");
}

std::string Environment::MakeCorpusPath(size_t shard_index) const {
  return std::filesystem::path(workdir).append(
      absl::StrFormat("corpus.%0*d", kDigitsInShardIndex, shard_index));
}

std::string Environment::MakeFeaturesPath(size_t shard_index) const {
  return std::filesystem::path(MakeCoverageDirPath())
      .append(
          absl::StrFormat("features.%0*d", kDigitsInShardIndex, shard_index));
}

std::string Environment::MakeDistilledPath() const {
  return std::filesystem::path(workdir).append(absl::StrFormat(
      "distilled-%s.%0*d", binary_name, kDigitsInShardIndex, my_shard_index));
}

std::string Environment::MakeCoverageReportPath(
    std::string_view annotation) const {
  return std::filesystem::path(workdir).append(absl::StrFormat(
      "coverage-report-%s.%0*d%s.txt", binary_name, kDigitsInShardIndex,
      my_shard_index, NormalizeAnnotation(annotation)));
}

std::string Environment::MakeCorpusStatsPath(
    std::string_view annotation) const {
  return std::filesystem::path(workdir).append(absl::StrFormat(
      "corpus-stats-%s.%0*d%s.json", binary_name, kDigitsInShardIndex,
      my_shard_index, NormalizeAnnotation(annotation)));
}

std::string Environment::MakeSourceBasedCoverageRawProfilePath() const {
  // Pass %m to enable online merge mode: updates file in place instead of
  // replacing it %m is replaced by lprofGetLoadModuleSignature(void) which
  // should be consistent for a fixed binary
  return std::filesystem::path(MakeCoverageDirPath())
      .append(absl::StrFormat("clang_coverage.%0*d.%s.profraw",
                              kDigitsInShardIndex, my_shard_index, "%m"));
}

std::string Environment::MakeSourceBasedCoverageIndexedProfilePath() const {
  return std::filesystem::path(MakeCoverageDirPath())
      .append(absl::StrFormat("clang_coverage.profdata"));
}

std::string Environment::MakeSourceBasedCoverageReportPath(
    std::string_view annotation) const {
  return std::filesystem::path(workdir).append(absl::StrFormat(
      "source-coverage-report-%s.%0*d%s", binary_name, kDigitsInShardIndex,
      my_shard_index, NormalizeAnnotation(annotation)));
}

std::vector<std::string> Environment::EnumerateRawCoverageProfiles() const {
  // Unfortunately we have to enumerate the profiles from the filesystem since
  // clang-coverage generates its own hash of the binary to avoid collisions
  // between builds. We account for this in Centipede already with the
  // per-binary coverage directory but LLVM coverage (perhaps smartly) doesn't
  // trust the user to get this right. We could call __llvm_profile_get_filename
  // in the runner and plumb it back to us but this is simpler.
  const std::string dir_path = MakeCoverageDirPath();
  std::error_code dir_error;
  const auto dir_iter =
      std::filesystem::directory_iterator(dir_path, dir_error);
  if (dir_error) {
    LOG(ERROR) << "Failed to access coverage dir '" << dir_path
               << "': " << dir_error.message();
    return {};
  }
  std::vector<std::string> raw_profiles;
  for (const auto &entry : dir_iter) {
    if (entry.is_regular_file() && entry.path().extension() == ".profraw")
      raw_profiles.push_back(entry.path());
  }
  return raw_profiles;
}

std::string Environment::MakeRUsageReportPath(
    std::string_view annotation) const {
  return std::filesystem::path(workdir).append(absl::StrFormat(
      "rusage-report-%s.%0*d%s.txt", binary_name, kDigitsInShardIndex,
      my_shard_index, NormalizeAnnotation(annotation)));
}

bool Environment::DumpCorpusTelemetryInThisShard() const {
  // Corpus stats are global across all shards on all machines.
  return my_shard_index == 0 && telemetry_frequency != 0;
}

bool Environment::DumpRUsageTelemetryInThisShard() const {
  // Unlike the corpus stats, we want to measure/dump rusage stats for each
  // Centipede process running on a separate machine: assign that to the first
  // shard (i.e. thread) on the machine.
  return my_shard_index % num_threads == 0;
}

bool Environment::DumpTelemetryForThisBatch(size_t batch_index) const {
  // Always dump for batch 0 (i.e. at the beginning of execution).
  if (telemetry_frequency != 0 && batch_index == 0) {
    return true;
  }
  // Special mode for negative --telemetry_frequency: dump when batch_index
  // is a power-of-two and is >= than 2^abs(--telemetry_frequency).
  if (telemetry_frequency < 0 && batch_index >= (1 << -telemetry_frequency) &&
      ((batch_index - 1) & batch_index) == 0) {
    return true;
  }
  // Normal mode: dump when requested number of batches get processed.
  if (((telemetry_frequency > 0) && (batch_index % telemetry_frequency == 0))) {
    return true;
  }
  return false;
}

// Returns true if `value` is one of "1", "true".
// Returns true if `value` is one of "0", "false".
// CHECK-fails otherwise.
static bool GetBoolFlag(std::string_view value) {
  if (value == "0" || value == "false") return false;
  CHECK(value == "1" || value == "true") << value;
  return true;
}

// Returns `value` as a size_t, CHECK-fails on parse error.
static size_t GetIntFlag(std::string_view value) {
  size_t result{};
  CHECK(std::from_chars(value.begin(), value.end(), result).ec == std::errc())
      << value;
  return result;
}

void Environment::SetFlagForExperiment(std::string_view name,
                                       std::string_view value) {
  // TODO(kcc): support more flags, as needed.

  // Handle bool flags.
  absl::flat_hash_map<std::string, bool *> bool_flags{
      {"use_cmp_features", &use_cmp_features},
      {"use_auto_dictionary", &use_auto_dictionary},
      {"use_dataflow_features", &use_dataflow_features},
      {"use_counter_features", &use_counter_features},
      {"use_pcpair_features", &use_pcpair_features},
      {"use_coverage_frontier", &use_coverage_frontier},
      {"use_legacy_default_mutator", &use_legacy_default_mutator},
  };
  auto bool_iter = bool_flags.find(name);
  if (bool_iter != bool_flags.end()) {
    *bool_iter->second = GetBoolFlag(value);
    return;
  }

  // Handle int flags.
  absl::flat_hash_map<std::string, size_t *> int_flags{
      {"path_level", &path_level},
      {"callstack_level", &callstack_level},
      {"max_corpus_size", &max_corpus_size},
      {"max_len", &max_len},
      {"crossover_level", &crossover_level},
      {"mutate_batch_size", &mutate_batch_size},
  };
  auto int_iter = int_flags.find(name);
  if (int_iter != int_flags.end()) {
    *int_iter->second = GetIntFlag(value);
    return;
  }

  LOG(FATAL) << "Unknown flag for experiment: " << name << "=" << value;
}

void Environment::UpdateForExperiment() {
  if (experiment.empty()) return;

  // Parse the --experiments flag.
  struct Experiment {
    std::string flag_name;
    std::vector<std::string> flag_values;
  };
  std::vector<Experiment> experiments;
  for (auto flag : absl::StrSplit(this->experiment, ':', absl::SkipEmpty())) {
    std::vector<std::string> flag_and_value = absl::StrSplit(flag, '=');
    CHECK_EQ(flag_and_value.size(), 2) << flag;
    experiments.emplace_back(
        Experiment{flag_and_value[0], absl::StrSplit(flag_and_value[1], ',')});
  }

  // Count the number of flag combinations.
  size_t num_combinations = 1;
  for (const auto &exp : experiments) {
    CHECK_NE(exp.flag_values.size(), 0) << exp.flag_name;
    num_combinations *= exp.flag_values.size();
  }
  CHECK_GT(num_combinations, 0);
  CHECK_EQ(num_threads % num_combinations, 0)
      << VV(num_threads) << VV(num_combinations);

  // Update the flags for the current shard and compute experiment_name.
  CHECK_LT(my_shard_index, num_threads);
  size_t my_combination_num = my_shard_index % num_combinations;
  experiment_name.clear();
  experiment_flags.clear();
  // Reverse the flags.
  // This way, the flag combinations will go in natural order.
  // E.g. for --experiment='foo=1,2,3:bar=10,20' the order of combinations is
  //   foo=1 bar=10
  //   foo=1 bar=20
  //   foo=2 bar=10 ...
  // Alternative would be to iterate in reverse order with rbegin()/rend().
  std::reverse(experiments.begin(), experiments.end());
  for (const auto &exp : experiments) {
    size_t idx = my_combination_num % exp.flag_values.size();
    SetFlagForExperiment(exp.flag_name, exp.flag_values[idx]);
    my_combination_num /= exp.flag_values.size();
    experiment_name = std::to_string(idx) + experiment_name;
    experiment_flags =
        exp.flag_name + "=" + exp.flag_values[idx] + ":" + experiment_flags;
  }
  experiment_name = "E" + experiment_name;
  load_other_shard_frequency = 0;  // The experiments should be independent.
}

void Environment::ReadKnobsFileIfSpecified() {
  const std::string_view knobs_file_path = knobs_file;
  if (knobs_file_path.empty()) return;
  ByteArray knob_bytes;
  auto *f = RemoteFileOpen(knobs_file, "r");
  CHECK(f) << "Failed to open remote file " << knobs_file;
  RemoteFileRead(f, knob_bytes);
  RemoteFileClose(f);
  VLOG(1) << "Knobs: " << knob_bytes.size() << " knobs read from "
          << knobs_file;
  knobs.Set(knob_bytes);
  knobs.ForEachKnob([](std::string_view name, Knobs::value_type value) {
    VLOG(1) << "knob " << name << ": " << static_cast<uint32_t>(value);
  });
}

}  // namespace centipede
