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

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>  // NOLINT
#include <iterator>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/nullability.h"
#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "./centipede/blob_file.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/centipede_default_callbacks.h"
#include "./centipede/centipede_interface.h"
#include "./centipede/corpus.h"
#include "./centipede/defs.h"
#include "./centipede/environment.h"
#include "./centipede/feature.h"
#include "./centipede/logging.h"
#include "./centipede/mutation_input.h"
#include "./centipede/runner_result.h"
#include "./centipede/shard_reader.h"
#include "./centipede/test_util.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"

namespace centipede {

namespace {

// A mock for CentipedeCallbacks.
class CentipedeMock : public CentipedeCallbacks {
 public:
  CentipedeMock(const Environment &env) : CentipedeCallbacks(env) {}
  // Doesn't execute anything
  // Sets `batch_result.results()` based on the values of `inputs`:
  // Collects various stats about the inputs, to be checked in tests.
  bool Execute(std::string_view binary, const std::vector<ByteArray> &inputs,
               BatchResult &batch_result) override {
    batch_result.results().clear();
    // For every input, we create a 256-element array `counters`, where
    // i-th element is the number of bytes with the value 'i' in the input.
    // `counters` is converted to FeatureVec and added to
    // `batch_result.results()`.
    for (auto &input : inputs) {
      ByteArray counters(256);
      for (uint8_t byte : input) {
        counters[byte]++;
      }
      FeatureVec features;
      for (size_t i = 0; i < counters.size(); ++i) {
        if (counters[i] == 0) continue;
        features.push_back(feature_domains::k8bitCounters.ConvertToMe(
            Convert8bitCounterToNumber(i, counters[i])));
      }
      batch_result.results().emplace_back(ExecutionResult{features});
      if (input.size() == 1) {
        observed_1byte_inputs_.insert(input[0]);
      } else {
        EXPECT_EQ(input.size(), 2);
        uint16_t input2bytes = (input[0] << 8) | input[1];
        observed_2byte_inputs_.insert(input2bytes);
      }
      num_inputs_++;
    }
    num_executions_++;
    max_batch_size_ = std::max(max_batch_size_, inputs.size());
    min_batch_size_ = std::min(min_batch_size_, inputs.size());
    return true;
  }
  // Makes predictable mutants:
  // first 255 mutations are 1-byte sequences {1} ... {255}.
  // (the value {0} is produced by the default GetSeeds()).
  // Next 65536 mutations are 2-byte sequences {0,0} ... {255, 255}.
  // Then repeat 2-byte sequences.
  void Mutate(const std::vector<MutationInputRef> &inputs, size_t num_mutants,
              std::vector<ByteArray> &mutants) override {
    mutants.resize(num_mutants);
    for (auto &mutant : mutants) {
      num_mutations_++;
      if (num_mutations_ < 256) {
        mutant = {static_cast<uint8_t>(num_mutations_)};
        continue;
      }
      uint8_t byte0 = (num_mutations_ - 256) / 256;
      uint8_t byte1 = (num_mutations_ - 256) % 256;
      mutant = {byte0, byte1};
    }
  }

  absl::flat_hash_set<uint8_t> observed_1byte_inputs_;
  absl::flat_hash_set<uint16_t> observed_2byte_inputs_;

  size_t num_executions_ = 0;
  size_t num_inputs_ = 0;
  size_t num_mutations_ = 0;
  size_t max_batch_size_ = 0;
  size_t min_batch_size_ = -1;
};

// Returns the same CentipedeCallbacks object every time, never destroys it.
class MockFactory : public CentipedeCallbacksFactory {
 public:
  explicit MockFactory(CentipedeCallbacks &cb) : cb_(cb) {}
  absl::Nonnull<CentipedeCallbacks *> create(const Environment &env) override {
    return &cb_;
  }
  void destroy(CentipedeCallbacks *cb) override { EXPECT_EQ(cb, &cb_); }

 private:
  CentipedeCallbacks &cb_;
};

}  // namespace

TEST(Centipede, MockTest) {
  TempCorpusDir tmp_dir{test_info_->name()};
  Environment env;
  env.log_level = 0;  // Disable most of the logging in the test.
  env.workdir = tmp_dir.path();
  env.num_runs = 100000;  // Enough to run through all 1- and 2-byte inputs.
  env.batch_size = 7;     // Just some small number.
  env.require_pc_table = false;  // No PC table here.
  CentipedeMock mock(env);
  MockFactory factory(mock);
  CentipedeMain(env, factory);  // Run fuzzing with num_runs inputs.
  EXPECT_EQ(mock.num_inputs_, env.num_runs + 1);  // num_runs and one dummy.
  EXPECT_EQ(mock.num_mutations_, env.num_runs);
  EXPECT_EQ(mock.max_batch_size_, env.batch_size);
  EXPECT_EQ(mock.min_batch_size_, 1);  // 1 for dummy.
  EXPECT_EQ(tmp_dir.CountElementsInCorpusFile(0),
            511);  // except for the seed input {0}.
  EXPECT_EQ(mock.observed_1byte_inputs_.size(), 256);    // all 1-byte seqs.
  EXPECT_EQ(mock.observed_2byte_inputs_.size(), 65536);  // all 2-byte seqs.
}

static size_t CountFilesInDir(std::string_view dir_path) {
  const std::filesystem::directory_iterator dir_iter{dir_path};
  return std::distance(std::filesystem::begin(dir_iter),
                       std::filesystem::end(dir_iter));
}

TEST(Centipede, ReadFirstCorpusDir) {
  TempDir workdir_1{test_info_->name(), "workdir_1"};
  TempDir workdir_2{test_info_->name(), "workdir_2"};
  TempDir corpus_dir{test_info_->name(), "corpus"};
  Environment env;
  env.log_level = 0;  // Disable most of the logging in the test.
  env.workdir = workdir_1.path();
  env.num_runs = 100000;  // Enough to run through all 1- and 2-byte inputs.
  env.batch_size = 7;     // Just some small number.
  env.require_pc_table = false;  // No PC table here.
  env.corpus_dir.push_back(corpus_dir.path());

  // First, generate corpus files in corpus_dir.
  CentipedeMock mock_1(env);
  MockFactory factory_1(mock_1);
  CentipedeMain(env, factory_1);
  ASSERT_EQ(mock_1.observed_1byte_inputs_.size(), 256);    // all 1-byte seqs.
  ASSERT_EQ(mock_1.observed_2byte_inputs_.size(), 65536);  // all 2-byte seqs.
  ASSERT_EQ(CountFilesInDir(env.corpus_dir[0]),
            512);  // All 1-byte and 2-byte inputs.

  // Second, run without fuzzing using the same corpus_dir.
  env.workdir = workdir_2.path();
  env.num_runs = 0;
  CentipedeMock mock_2(env);
  MockFactory factory_2(mock_2);
  CentipedeMain(env, factory_2);
  // Should observe all inputs in corpus_dir.
  EXPECT_EQ(mock_2.num_inputs_, 512);
}

TEST(Centipede, DoesNotReadFirstCorpusDirIfOutputOnly) {
  TempDir workdir_1{test_info_->name(), "workdir_1"};
  TempDir workdir_2{test_info_->name(), "workdir_2"};
  TempDir corpus_dir{test_info_->name(), "corpus"};
  Environment env;
  env.log_level = 0;  // Disable most of the logging in the test.
  env.workdir = workdir_1.path();
  env.num_runs = 100000;  // Enough to run through all 1- and 2-byte inputs.
  env.batch_size = 7;     // Just some small number.
  env.require_pc_table = false;  // No PC table here.
  env.corpus_dir.push_back(corpus_dir.path());

  // First, generate corpus files in corpus_dir.
  CentipedeMock mock_1(env);
  MockFactory factory_1(mock_1);
  CentipedeMain(env, factory_1);
  ASSERT_EQ(mock_1.observed_1byte_inputs_.size(), 256);    // all 1-byte seqs.
  ASSERT_EQ(mock_1.observed_2byte_inputs_.size(), 65536);  // all 2-byte seqs.
  ASSERT_EQ(CountFilesInDir(env.corpus_dir[0]),
            512);  // All 1-byte and 2-byte inputs.

  // Second, run without fuzzing using the same corpus_dir, but as output-only.
  env.workdir = workdir_2.path();
  env.num_runs = 0;
  env.first_corpus_dir_output_only = true;
  CentipedeMock mock_2(env);
  MockFactory factory_2(mock_2);
  CentipedeMain(env, factory_2);
  // Should observe no inputs other than the seed input {0}.
  EXPECT_EQ(mock_2.num_inputs_, 1);
}

TEST(Centipede, SkipsOutputIfFirstCorpusDirIsEmptyPath) {
  TempCorpusDir tmp_dir{test_info_->name()};
  Environment env;
  env.log_level = 0;  // Disable most of the logging in the test.
  env.workdir = tmp_dir.path();
  env.num_runs = 100000;  // Enough to run through all 1- and 2-byte inputs.
  env.batch_size = 7;     // Just some small number.
  env.require_pc_table = false;  // No PC table here.
  // Set the first corpus_dir entry to empty path to skip output.
  env.corpus_dir.push_back("");
  env.corpus_dir.push_back(tmp_dir.CreateSubdir("cd"));

  CentipedeMock mock(env);
  MockFactory factory(mock);
  CentipedeMain(env, factory);  // Run fuzzing with num_runs inputs.
  EXPECT_EQ(mock.observed_1byte_inputs_.size(), 256);    // all 1-byte seqs.
  EXPECT_EQ(mock.observed_2byte_inputs_.size(), 65536);  // all 2-byte seqs.
  // No output should be in other entires of corpus_dir.
  EXPECT_EQ(CountFilesInDir(env.corpus_dir[1]), 0);
}

// Tests fuzzing and distilling in multiple shards.
TEST(Centipede, ShardsAndDistillTest) {
  TempCorpusDir tmp_dir{test_info_->name()};
  Environment env;
  env.workdir = tmp_dir.path();
  env.log_level = 0;  // Disable most of the logging in the test.
  size_t combined_num_runs = 100000;  // Enough to run through all inputs.
  env.total_shards = 20;
  env.num_runs = combined_num_runs / env.total_shards;
  env.require_pc_table = false;  // No PC table here.

  // Create two empty dirs and add them to corpus_dir.
  env.corpus_dir.push_back(tmp_dir.CreateSubdir("cd1"));
  env.corpus_dir.push_back(tmp_dir.CreateSubdir("cd2"));

  CentipedeMock mock(env);
  // First round of runs: do the actual fuzzing, compute the features.
  size_t max_shard_size = 0;
  for (size_t shard_index = 0; shard_index < env.total_shards; shard_index++) {
    env.my_shard_index = shard_index;
    MockFactory factory(mock);
    CentipedeMain(env, factory);  // Run fuzzing in shard `shard_index`.
    auto corpus_size = tmp_dir.CountElementsInCorpusFile(shard_index);
    // Every byte should be present at least once.
    // With 2-byte inputs, we get at least 128 inputs covering 256 features.
    EXPECT_GT(corpus_size, 128);
    max_shard_size = std::max(max_shard_size, corpus_size);
  }
  EXPECT_EQ(mock.observed_1byte_inputs_.size(), 256);    // all 1-byte seqs.
  EXPECT_EQ(mock.observed_2byte_inputs_.size(), 65536);  // all 2-byte seqs.

  EXPECT_GT(CountFilesInDir(env.corpus_dir[0]), 128);
  EXPECT_EQ(CountFilesInDir(env.corpus_dir[1]), 0);

  // Second round of runs. Don't fuzz, only distill.
  // Don't distill in the last one to test the flag behaviour.
  env.distill = true;
  env.num_threads = env.total_shards - 1;
  env.my_shard_index = 0;
  // Empty the corpus_dir[0]
  std::filesystem::remove_all(env.corpus_dir[0]);
  std::filesystem::create_directory(env.corpus_dir[0]);
  MockFactory factory(mock);
  CentipedeMain(env, factory);  // Run distilling in shard `shard_index`.
  EXPECT_EQ(CountFilesInDir(env.corpus_dir[0]), 0);
  for (size_t shard_index = 0; shard_index < env.total_shards; shard_index++) {
    SCOPED_TRACE(absl::StrCat("Shard ", shard_index));
    auto distilled_size =
        tmp_dir.CountElementsInCorpusFile(shard_index, "distilled-.");
    if (shard_index == env.total_shards - 1) {
      // Didn't distill in the last shard.
      EXPECT_EQ(distilled_size, 0);
    } else {
      // Distillation is expected to find more inputs than any individual shard.
      EXPECT_GT(distilled_size, max_shard_size);
      // And since we are expecting 512 features, with 2-byte inputs,
      // we get at least 512/2 corpus elements after distillation.
      EXPECT_GT(distilled_size, 256);
    }
  }
}

// Tests --input_filter. test_input_filter filters out inputs with 'b' in them.
TEST(Centipede, InputFilter) {
  TempCorpusDir tmp_dir{test_info_->name()};
  Environment env;
  env.workdir = tmp_dir.path();
  env.num_runs = 256;            // Enough to run through all 1- byte inputs.
  env.log_level = 0;             // Disable most of the logging in the test.
  env.require_pc_table = false;  // No PC table here.
  // Add %f so that test_input_filter doesn't need to be linked with forkserver.
  env.input_filter = "%f" + std::string{GetDataDependencyFilepath(
                                "centipede/testing/test_input_filter")};
  CentipedeMock mock(env);
  MockFactory factory(mock);
  CentipedeMain(env, factory);  // Run fuzzing.
  auto corpus = tmp_dir.GetCorpus(0);
  std::set<ByteArray> corpus_set(corpus.begin(), corpus.end());
  EXPECT_FALSE(corpus_set.count({'b'}));
  EXPECT_TRUE(corpus_set.count({'a'}));
  EXPECT_TRUE(corpus_set.count({'c'}));
}

// Callbacks for MutateViaExternalBinary test.
class MutateCallbacks : public CentipedeCallbacks {
 public:
  explicit MutateCallbacks(const Environment &env) : CentipedeCallbacks(env) {}
  // Will not be called.
  bool Execute(std::string_view binary, const std::vector<ByteArray> &inputs,
               BatchResult &batch_result) override {
    CHECK(false);
    return false;
  }

  // Will not be called.
  void Mutate(const std::vector<MutationInputRef> &inputs, size_t num_mutants,
              std::vector<ByteArray> &mutants) override {
    CHECK(false);
  }

  // Redeclare a protected member function as public so the tests can call it.
  using CentipedeCallbacks::MutateViaExternalBinary;
};

TEST(Centipede, MutateViaExternalBinary) {
  // This binary contains a test-friendly custom mutator.
  const std::string binary_with_custom_mutator =
      GetDataDependencyFilepath("centipede/testing/test_fuzz_target");
  // This binary does not contain a custom mutator.
  const std::string binary_without_custom_mutator =
      GetDataDependencyFilepath("centipede/testing/abort_fuzz_target");
  // Mutate a couple of different inputs.
  std::vector<ByteArray> inputs = {{0, 1, 2}, {3, 4}};
  // The custom mutator in the test binary will revert the order of bytes
  // and sometimes add a number in [100-107) at the end.
  // Periodically, the custom mutator will fall back to LLVMFuzzerMutate,
  // which in turn will sometimes shrink the inputs.
  std::vector<ByteArray> some_of_expected_mutants = {
      // Reverted inputs, sometimes with an extra byte at the end.
      {2, 1, 0},
      {2, 1, 0, 100},
      {2, 1, 0, 101},
      {2, 1, 0, 102},
      {4, 3},
      {4, 3, 103},
      {4, 3, 104},
      {4, 3, 105},
      // Shrunk inputs.
      {0, 1},
      {4}};

  std::vector<ByteArray> expected_crossover_mutants = {
      // Crossed-over mutants.
      {0, 1, 2, 42, 3, 4},
      {3, 4, 42, 0, 1, 2},
  };

  auto all_expected_mutants = some_of_expected_mutants;
  all_expected_mutants.insert(all_expected_mutants.end(),
                              expected_crossover_mutants.begin(),
                              expected_crossover_mutants.end());
  std::vector<ByteArray> mutants;

  // Test with crossover enabled (default).
  {
    Environment env;
    MutateCallbacks callbacks(env);

    // Expect to fail on the binary w/o a custom mutator.
    mutants.resize(1);
    EXPECT_FALSE(callbacks.MutateViaExternalBinary(
        binary_without_custom_mutator,
        GetMutationInputRefsFromDataInputs(inputs), mutants));
    // Expect to succeed on the binary with a custom mutator.
    mutants.resize(10000);
    EXPECT_TRUE(callbacks.MutateViaExternalBinary(
        binary_with_custom_mutator, GetMutationInputRefsFromDataInputs(inputs),
        mutants));
    // Check that we see all expected mutants, and that they are non-empty.
    for (auto &mutant : mutants) {
      EXPECT_FALSE(mutant.empty());
    }
    EXPECT_THAT(mutants, testing::IsSupersetOf(all_expected_mutants));
  }

  // Test with crossover disabled.
  {
    Environment env_no_crossover;
    env_no_crossover.crossover_level = 0;
    MutateCallbacks callbacks_no_crossover(env_no_crossover);
    mutants.resize(10000);
    EXPECT_TRUE(callbacks_no_crossover.MutateViaExternalBinary(
        binary_with_custom_mutator, GetMutationInputRefsFromDataInputs(inputs),
        mutants));
    // Must contain normal mutants, but not the ones from crossover.
    EXPECT_THAT(mutants, testing::IsSupersetOf(some_of_expected_mutants));
    for (const auto &crossover_mutant : expected_crossover_mutants) {
      EXPECT_THAT(mutants, testing::Contains(crossover_mutant).Times(0));
    }
  }
}

// A mock for MergeFromOtherCorpus test.
class MergeMock : public CentipedeCallbacks {
 public:
  explicit MergeMock(const Environment &env) : CentipedeCallbacks(env) {}

  // Doesn't execute anything.
  // All inputs are 1-byte long.
  // For an input {X}, the feature output is {X}.
  bool Execute(std::string_view binary, const std::vector<ByteArray> &inputs,
               BatchResult &batch_result) override {
    batch_result.results().resize(inputs.size());
    for (size_t i = 0, n = inputs.size(); i < n; ++i) {
      CHECK_EQ(inputs[i].size(), 1);
      batch_result.results()[i].mutable_features() = {inputs[i][0]};
    }
    return true;
  }

  // Every consecutive mutation is {number_of_mutations_} (starting from 1).
  void Mutate(const std::vector<MutationInputRef> &inputs, size_t num_mutants,
              std::vector<ByteArray> &mutants) override {
    mutants.resize(num_mutants);
    for (auto &mutant : mutants) {
      mutant.resize(1);
      mutant[0] = ++number_of_mutations_;
    }
  }

  void Reset() { number_of_mutations_ = 0; }

 private:
  size_t number_of_mutations_ = 0;
};

TEST(Centipede, MergeFromOtherCorpus) {
  using Corpus = std::vector<ByteArray>;

  // Set up the workdir, create a 2-shard corpus with 3 inputs each.
  TempCorpusDir work_tmp_dir{test_info_->name(), "workdir"};
  Environment env;
  env.workdir = work_tmp_dir.path();
  env.num_runs = 3;              // Just a few runs.
  env.require_pc_table = false;  // No PC table here.
  MergeMock mock(env);
  MockFactory factory(mock);
  for (env.my_shard_index = 0; env.my_shard_index < 2; ++env.my_shard_index) {
    CentipedeMain(env, factory);
  }
  CentipedeMain(env, factory);
  EXPECT_EQ(work_tmp_dir.GetCorpus(0), Corpus({{1}, {2}, {3}}));
  EXPECT_EQ(work_tmp_dir.GetCorpus(1), Corpus({{4}, {5}, {6}}));

  // Set up another workdir, create a 2-shard corpus there, with 4 inputs each.
  TempCorpusDir merge_tmp_dir(test_info_->name(), "merge_from");
  Environment merge_env;
  merge_env.workdir = merge_tmp_dir.path();
  merge_env.num_runs = 4;
  merge_env.require_pc_table = false;  // No PC table here.
  mock.Reset();
  for (merge_env.my_shard_index = 0; merge_env.my_shard_index < 2;

       ++merge_env.my_shard_index) {
    CentipedeMain(merge_env, factory);
  }
  EXPECT_EQ(merge_tmp_dir.GetCorpus(0), Corpus({{1}, {2}, {3}, {4}}));
  EXPECT_EQ(merge_tmp_dir.GetCorpus(1), Corpus({{5}, {6}, {7}, {8}}));

  // Merge shards of `merge_env` into shards of `env`.
  // Shard 0 will receive one extra input: {4}
  // Shard 1 will receive two extra inputs: {7}, {8}
  env.merge_from = merge_tmp_dir.path();
  env.num_runs = 0;
  for (env.my_shard_index = 0; env.my_shard_index < 2; ++env.my_shard_index) {
    CentipedeMain(env, factory);
  }
  EXPECT_EQ(work_tmp_dir.GetCorpus(0), Corpus({{1}, {2}, {3}, {4}}));
  EXPECT_EQ(work_tmp_dir.GetCorpus(1), Corpus({{4}, {5}, {6}, {7}, {8}}));
}

// A mock for FunctionFilter test.
class FunctionFilterMock : public CentipedeCallbacks {
 public:
  explicit FunctionFilterMock(const Environment &env)
      : CentipedeCallbacks(env) {
    std::vector<ByteArray> seed_inputs;
    const size_t num_seeds_available = GetSeeds(/*num_seeds=*/1, seed_inputs);
    CHECK_EQ(num_seeds_available, 1) << "Default seeds must have size one.";
    CHECK_EQ(seed_inputs.size(), 1) << "Default seeds must have size one.";
    seed_inputs_.insert(seed_inputs.begin(), seed_inputs.end());
  }

  // Executes the target in the normal way.
  bool Execute(std::string_view binary, const std::vector<ByteArray> &inputs,
               BatchResult &batch_result) override {
    return ExecuteCentipedeSancovBinaryWithShmem(env_.binary, inputs,
                                                 batch_result) == EXIT_SUCCESS;
  }

  // Sets the inputs to one of 3 pre-defined values.
  void Mutate(const std::vector<MutationInputRef> &inputs, size_t num_mutants,
              std::vector<ByteArray> &mutants) override {
    mutants.resize(num_mutants);
    for (auto &input : inputs) {
      if (!seed_inputs_.contains(input.data)) {
        observed_inputs_.insert(input.data);
      }
    }
    for (auto &mutant : mutants) {
      mutant = GetMutant(++number_of_mutations_);
    }
  }

  // Returns one of 3 pre-defined values, that trigger different code paths in
  // the test target.
  static ByteArray GetMutant(size_t idx) {
    const char *mutants[3] = {"func1", "func2-A", "foo"};
    const char *mutant = mutants[idx % 3];
    return {mutant, mutant + strlen(mutant)};
  }

  // Seed inputs generated from GetSeeds().
  absl::flat_hash_set<ByteArray> seed_inputs_;
  // Set of inputs observed by Mutate(), except for seed inputs.
  absl::flat_hash_set<ByteArray> observed_inputs_;

 private:
  size_t number_of_mutations_ = 0;
};

// Runs a short fuzzing session with the provided `function_filter`.
// Returns a sorted array of observed inputs.
static std::vector<ByteArray> RunWithFunctionFilter(
    std::string_view function_filter, const TempDir &tmp_dir) {
  Environment env;
  env.workdir = tmp_dir.path();
  env.seed = 1;  // make the runs predictable.
  env.num_runs = 100;
  env.batch_size = 10;
  env.binary = GetDataDependencyFilepath("centipede/testing/test_fuzz_target");
  env.coverage_binary = env.binary;
  // Must symbolize in order for the filter to work.
  env.symbolizer_path = GetLLVMSymbolizerPath();
  env.objdump_path = GetObjDumpPath();
  env.log_level = 0;
  env.function_filter = function_filter;
  FunctionFilterMock mock(env);
  MockFactory factory(mock);
  CentipedeMain(env, factory);
  LOG(INFO) << mock.observed_inputs_.size();
  std::vector<ByteArray> res(mock.observed_inputs_.begin(),
                             mock.observed_inputs_.end());
  std::sort(res.begin(), res.end());
  return res;
}

// Tests --function_filter.
TEST(Centipede, FunctionFilter) {
  // Run with empty function filter.
  {
    TempDir tmp_dir{test_info_->name(), "none"};
    auto observed_empty = RunWithFunctionFilter("", tmp_dir);
    ASSERT_EQ(observed_empty.size(), 3);
  }

  // Run with a one-function filter
  {
    TempDir tmp_dir{test_info_->name(), "single"};
    auto observed_single = RunWithFunctionFilter("SingleEdgeFunc", tmp_dir);
    ASSERT_EQ(observed_single.size(), 1);
    EXPECT_EQ(observed_single[0], FunctionFilterMock::GetMutant(0));
  }

  // Run with a two-function filter.
  {
    TempDir tmp_dir{test_info_->name(), "single_multi"};
    auto observed_both =
        RunWithFunctionFilter("SingleEdgeFunc,MultiEdgeFunc", tmp_dir);
    ASSERT_EQ(observed_both.size(), 2);
    EXPECT_EQ(observed_both[0], FunctionFilterMock::GetMutant(0));
    EXPECT_EQ(observed_both[1], FunctionFilterMock::GetMutant(1));
  }
}

namespace {

// A mock for ExtraBinaries test.
class ExtraBinariesMock : public CentipedeCallbacks {
 public:
  explicit ExtraBinariesMock(const Environment &env)
      : CentipedeCallbacks(env) {}

  // Doesn't execute anything.
  // On certain combinations of {binary,input} returns false.
  bool Execute(std::string_view binary, const std::vector<ByteArray> &inputs,
               BatchResult &batch_result) override {
    bool res = true;
    for (const auto &input : inputs) {
      if (input.size() != 1) continue;
      if (binary == "b1" && input[0] == 10) res = false;
      if (binary == "b2" && input[0] == 30) res = false;
      if (binary == "b3" && input[0] == 50) res = false;
    }
    batch_result.results().resize(inputs.size());
    return res;
  }

  // Sets the mutants to different 1-byte values.
  void Mutate(const std::vector<MutationInputRef> &inputs, size_t num_mutants,
              std::vector<ByteArray> &mutants) override {
    mutants.resize(num_mutants);
    for (auto &mutant : mutants) {
      mutant.resize(1);
      mutant[0] = ++number_of_mutations_;
    }
  }

 private:
  size_t number_of_mutations_ = 0;
};

}  // namespace

// Tests --extra_binaries.
// Executes one main binary (--binary) and 3 extra ones (--extra_binaries).
// Expects the main binary and two extra ones to generate one crash each.
TEST(Centipede, ExtraBinaries) {
  TempDir tmp_dir{test_info_->name()};
  Environment env;
  env.workdir = tmp_dir.path();
  env.num_runs = 100;
  env.batch_size = 10;
  env.log_level = 1;
  env.binary = "b1";
  env.extra_binaries = {"b2", "b3", "b4"};
  env.require_pc_table = false;  // No PC table here.
  ExtraBinariesMock mock(env);
  MockFactory factory(mock);
  CentipedeMain(env, factory);

  // Verify that we see the expected crashes.
  // The "crashes" dir must contain 3 crashy inputs, one for each binary.
  // We simply match their file names, because they are hashes of the contents.
  std::vector<std::string> found_crash_file_names;
  auto crashes_dir_path = WorkDir{env}.CrashReproducerDirPath();
  ASSERT_TRUE(std::filesystem::exists(crashes_dir_path))
      << VV(crashes_dir_path);
  for (const auto &dir_ent :
       std::filesystem::directory_iterator(crashes_dir_path)) {
    found_crash_file_names.push_back(dir_ent.path().filename());
  }
  EXPECT_THAT(found_crash_file_names, testing::UnorderedElementsAre(
                                          Hash({10}), Hash({30}), Hash({50})));
}

namespace {

// A mock for UndetectedCrashingInput test.
class UndetectedCrashingInputMock : public CentipedeCallbacks {
 public:
  explicit UndetectedCrashingInputMock(const Environment &env,
                                       size_t crashing_input_idx)
      : CentipedeCallbacks{env}, crashing_input_idx_{crashing_input_idx} {
    CHECK_LE(crashing_input_idx_, std::numeric_limits<uint8_t>::max());
  }

  // Doesn't execute anything.
  // Crash when 0th char of input to binary b1 equals 10, but only on 1st exec.
  bool Execute(std::string_view binary, const std::vector<ByteArray> &inputs,
               BatchResult &batch_result) override {
    batch_result.ClearAndResize(inputs.size());
    bool res = true;
    for (const auto &input : inputs) {
      CHECK_EQ(input.size(), 1);  // By construction in `Mutate()`.
      // The contents of each mutant is its sequential number.
      if (input[0] == crashing_input_idx_) {
        if (first_pass_) {
          first_pass_ = false;
          crashing_input_ = input;
          // TODO(b/274705740): `num_outputs_read()` is the number of outputs
          //  that Centipede engine *expects* to have been read from *the
          //  current BatchResult* by the *particular* implementation of
          //  `CentipedeCallbacks` (and `DefaultCentipedeCallbacks` fits the
          //  bill). `Centipede::ReportCrash()` then uses this value as a hint
          //  for the crashing input's index, and in our case saves the batch's
          //  inputs from 0 up to and including the crasher to a subdir. See the
          //  bug for details. All of this is horribly convoluted and misplaced
          //  here. Implement a cleaner solution.
          batch_result.num_outputs_read() =
              crashing_input_idx_ % env_.batch_size;
          res = false;
        }
      }
    }
    return res;
  }

  // Sets the mutants to different 1-byte values.
  void Mutate(const std::vector<MutationInputRef> &inputs, size_t num_mutants,
              std::vector<ByteArray> &mutants) override {
    mutants.resize(num_mutants);
    for (auto &mutant : mutants) {
      // The contents of each mutant is simply its sequential number.
      mutant = {static_cast<uint8_t>(curr_input_idx_++)};
    }
  }

  // Gets the input that triggered the crash.
  ByteArray crashing_input() const { return crashing_input_; }

 private:
  const size_t crashing_input_idx_;
  size_t curr_input_idx_ = 0;
  ByteArray crashing_input_ = {};
  bool first_pass_ = true;
};

}  // namespace

// Test for preserving a crashing batch when 1-by-1 exec fails to reproduce.
// Executes one main binary (--binary).
// Expects the binary to crash once and 1-by-1 reproduction to fail.
TEST(Centipede, UndetectedCrashingInput) {
  constexpr size_t kNumBatches = 7;
  constexpr size_t kBatchSize = 11;
  constexpr size_t kCrashingInputIdxInBatch = kBatchSize / 2;
  constexpr size_t kCrashingInputIdx =
      (kNumBatches / 2) * kBatchSize + kCrashingInputIdxInBatch;

  LOG(INFO) << VV(kNumBatches) << VV(kBatchSize)
            << VV(kCrashingInputIdxInBatch) VV(kCrashingInputIdx);

  TempDir temp_dir{test_info_->name()};
  Environment env;
  env.workdir = temp_dir.path();
  env.num_runs = kBatchSize * kNumBatches;
  env.batch_size = kBatchSize;
  // No real binary: prevent attempts by Centipede to read a PCtable from it.
  env.require_pc_table = false;

  UndetectedCrashingInputMock mock(env, kCrashingInputIdx);
  MockFactory factory(mock);
  CentipedeMain(env, factory);

  // Verify that we see the expected inputs from the batch.
  // The "crashes/unreliable_batch-<HASH>" dir must contain all inputs from the
  // batch that were executing during the session.
  // We simply verify the number of saved inputs matches the number of executed
  // inputs.
  const auto crashing_input_hash = Hash(mock.crashing_input());
  const auto crashes_dir_path = std::filesystem::path(temp_dir.path())
                                    .append("crashes")
                                    .append("crashing_batch-")
                                    .concat(crashing_input_hash);
  ASSERT_TRUE(std::filesystem::exists(crashes_dir_path)) << crashes_dir_path;
  std::vector<std::string> found_crash_file_names;
  for (auto const &dir_ent :
       std::filesystem::directory_iterator(crashes_dir_path)) {
    found_crash_file_names.push_back(dir_ent.path().filename());
  }
  // TODO(ussuri): Verify exact names/contents of the files, not just count.
  ASSERT_EQ(found_crash_file_names.size(), kCrashingInputIdxInBatch + 1);
}

static void WriteBlobsToFile(const std::vector<ByteArray> &blobs,
                             const std::string_view path) {
  auto appender = DefaultBlobFileWriterFactory();
  CHECK_OK(appender->Open(path, "a"));
  for (const auto &blob : blobs) {
    CHECK_OK(appender->Write(blob));
  }
}

TEST(Centipede, ShardReader) {
  ByteArray data1 = {1, 2, 3};
  ByteArray data2 = {3, 4, 5, 6};
  ByteArray data3 = {7, 8, 9, 10, 11};
  ByteArray data4 = {12, 13, 14};
  ByteArray data5 = {15, 16};
  FeatureVec fv1 = {100, 200, 300};
  FeatureVec fv2 = {300, 400, 500, 600};
  FeatureVec fv3 = {700, 800, 900, 1000, 1100};
  FeatureVec fv4 = {};  // empty.

  std::vector<ByteArray> corpus_blobs;
  corpus_blobs.push_back(data1);
  corpus_blobs.push_back(data2);
  corpus_blobs.push_back(data3);
  corpus_blobs.push_back(data4);
  corpus_blobs.push_back(data5);

  std::vector<ByteArray> features_blobs;
  features_blobs.push_back(PackFeaturesAndHash(data1, fv1));
  features_blobs.push_back(PackFeaturesAndHash(data2, fv2));
  features_blobs.push_back(PackFeaturesAndHash(data3, fv3));
  features_blobs.push_back(PackFeaturesAndHash(data4, fv4));

  TempDir tmp_dir{test_info_->name()};
  std::string corpus_path = tmp_dir.GetFilePath("corpus");
  std::string features_path = tmp_dir.GetFilePath("features");
  WriteBlobsToFile(corpus_blobs, corpus_path);
  WriteBlobsToFile(features_blobs, features_path);

  std::vector<CorpusRecord> res;
  ReadShard(corpus_path, features_path,
            [&res](const ByteArray &input, const FeatureVec &features) {
              res.push_back(CorpusRecord{input, features});
            });

  EXPECT_EQ(res.size(), 5UL);
  EXPECT_EQ(res[0].data, data1);
  EXPECT_EQ(res[1].data, data2);
  EXPECT_EQ(res[2].data, data3);
  EXPECT_EQ(res[3].data, data4);
  EXPECT_EQ(res[4].data, data5);
  EXPECT_EQ(res[0].features, fv1);
  EXPECT_EQ(res[1].features, fv2);
  EXPECT_EQ(res[2].features, fv3);
  EXPECT_EQ(res[3].features, FeatureVec{feature_domains::kNoFeature});
  EXPECT_EQ(res[4].features, FeatureVec());
}

TEST(Centipede, GetsSeedInputs) {
  Environment env;
  env.binary =
      GetDataDependencyFilepath("centipede/testing/seeded_fuzz_target");
  CentipedeDefaultCallbacks callbacks(env);
  std::vector<ByteArray> seeds;
  EXPECT_EQ(callbacks.GetSeeds(10, seeds), 10);
  EXPECT_THAT(seeds, testing::ContainerEq(std::vector<ByteArray>{
                         {0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}}));
  EXPECT_EQ(callbacks.GetSeeds(5, seeds), 10);
  EXPECT_THAT(seeds, testing::ContainerEq(
                         std::vector<ByteArray>{{0}, {1}, {2}, {3}, {4}}));
  EXPECT_EQ(callbacks.GetSeeds(100, seeds), 10);
  EXPECT_THAT(seeds, testing::ContainerEq(std::vector<ByteArray>{
                         {0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}}));
}

TEST(Centipede, CleansUpMetadataAfterStartup) {
  Environment env;
  env.binary = GetDataDependencyFilepath(
      "centipede/testing/expensive_startup_fuzz_target");
  CentipedeDefaultCallbacks callbacks(env);
  BatchResult batch_result;
  const std::vector<ByteArray> inputs = {{0}};
  ASSERT_TRUE(callbacks.Execute(env.binary, inputs, batch_result));
  ASSERT_EQ(batch_result.results().size(), 1);
  bool found_startup_cmp_entry = false;
  batch_result.results()[0].metadata().ForEachCmpEntry(
      [&](ByteSpan a, ByteSpan b) {
        if (a == ByteArray{'F', 'u', 'z', 'z'}) found_startup_cmp_entry = true;
        if (b == ByteArray{'F', 'u', 'z', 'z'}) found_startup_cmp_entry = true;
      });
  EXPECT_FALSE(found_startup_cmp_entry);
}

}  // namespace centipede
