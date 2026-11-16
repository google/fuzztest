// Copyright 2026 The Centipede Authors.
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

#include "./centipede/diff_baseline.h"

#include <cstdlib>
#include <filesystem>  // NOLINT
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./centipede/environment.h"
#include "./centipede/execution_metadata.h"
#include "./centipede/runner_result.h"
#include "./centipede/stop.h"
#include "./centipede/util.h"
#include "./common/defs.h"
#include "./common/hash.h"
#include "./common/test_util.h"

namespace fuzztest::internal {
namespace {

using ::testing::IsEmpty;
using ::testing::Optional;

class DiffBaselineTest : public ::testing::Test {
 protected:
  DiffBaselineTest()
      : root_(::testing::UnitTest::GetInstance()->current_test_info()->name()),
        env_([this] {
          Environment env;
          env.fuzztest_workdir_root = root_.path().string();
          env.fuzztest_binary_identifier = "pkg/bin";
          env.test_name = "Suite.Test";
          env.fuzztest_only_replay = true;
          return env;
        }()) {}

  void SetUp() override { DiffStats::Global().Reset(); }
  void TearDown() override { DiffStats::Global().Reset(); }

  Environment EnvWithMode(std::string mode) const {
    Environment env = env_;
    env.fuzztest_diff_mode = std::move(mode);
    return env;
  }

  static ByteArray Bytes(std::string_view s) {
    return ByteArray(s.begin(), s.end());
  }

  static void WriteBaseline(const Environment& env, ByteSpan input,
                            std::string_view container) {
    const std::string test_dir = DiffBaselineTestDir(env);
    std::filesystem::create_directories(test_dir);
    WriteToLocalFile((std::filesystem::path(test_dir) / Hash(input)).string(),
                     Bytes(container));
  }

  static std::string ReadFileOrDie(const std::string& path) {
    std::string contents;
    ReadFromLocalFile(path, contents);
    return contents;
  }

  TempDir root_;
  Environment env_;
};

TEST_F(DiffBaselineTest, LayoutIsUnderWorkdirRootBaseline) {
  const Environment env = EnvWithMode("record");
  EXPECT_EQ(DiffBaselineBinaryDir(env),
            (root_.path() / "baseline" / "pkg/bin").string());
  EXPECT_EQ(DiffBaselineTestDir(env),
            (root_.path() / "baseline" / "pkg/bin" / "Suite.Test").string());
}

TEST_F(DiffBaselineTest, ActiveOnlyInReplayWithValidDiffModeAndNoWildcards) {
  EXPECT_FALSE(IsDiffActive(EnvWithMode("")));
  EXPECT_FALSE(IsDiffActive(EnvWithMode("none")));
  EXPECT_FALSE(IsDiffActive(EnvWithMode("bogus")));
  EXPECT_TRUE(IsDiffRecord(EnvWithMode("record")));
  EXPECT_FALSE(IsDiffValidate(EnvWithMode("record")));
  EXPECT_TRUE(IsDiffValidate(EnvWithMode("validate")));
  Environment not_replay = EnvWithMode("record");
  not_replay.fuzztest_only_replay = false;
  EXPECT_FALSE(IsDiffActive(not_replay));
  Environment replay_crash = EnvWithMode("validate");
  replay_crash.replay_crash = true;
  EXPECT_FALSE(IsDiffActive(replay_crash));
  Environment wildcards = EnvWithMode("validate");
  wildcards.has_input_wildcards = true;
  EXPECT_FALSE(IsDiffActive(wildcards));
  EXPECT_FALSE(DiffBaselineStore(not_replay).active());
}

TEST_F(DiffBaselineTest, PrepareRejectsInvalidDiffModeAndRelativeWorkdirRoot) {
  {
    const Environment invalid_mode = EnvWithMode("typo");
    StopCondition stop;
    PrepareDiffBaselineForTest(invalid_mode, stop);
    StopCondition::StopRequest request;
    ASSERT_TRUE(stop.StopRequested(&request));
    EXPECT_EQ(request.exit_code, EXIT_FAILURE);
  }
  {
    Environment relative_root = EnvWithMode("record");
    relative_root.fuzztest_workdir_root = "relative/workdir";
    StopCondition stop;
    PrepareDiffBaselineForTest(relative_root, stop);
    StopCondition::StopRequest request;
    ASSERT_TRUE(stop.StopRequested(&request));
    EXPECT_EQ(request.exit_code, EXIT_FAILURE);
    EXPECT_FALSE(DiffBaselineStore(relative_root).active());
  }
}

TEST_F(DiffBaselineTest, RecordResetsTheTestDirectoryAndSaves) {
  const Environment env = EnvWithMode("record");
  const std::string test_dir = DiffBaselineTestDir(env);
  std::filesystem::create_directories(test_dir);
  WriteToLocalFile((std::filesystem::path(test_dir) / "stale").string(),
                   Bytes("old"));
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);
  EXPECT_FALSE(stop.StopRequested());
  EXPECT_TRUE(std::filesystem::is_directory(test_dir));
  EXPECT_FALSE(
      std::filesystem::exists(std::filesystem::path(test_dir) / "stale"));

  DiffBaselineStore store(env);
  ASSERT_TRUE(store.active());
  const ByteArray input = Bytes("input");
  const std::string hash = Hash(input);
  ASSERT_TRUE(store.Save(hash, Bytes("container")).ok());
  EXPECT_EQ(ReadFileOrDie((std::filesystem::path(test_dir) / hash).string()),
            "container");
  EXPECT_EQ(hash.size(), 40);
}

TEST_F(DiffBaselineTest, LookupReadsAndCaches) {
  const Environment env = EnvWithMode("validate");
  const ByteArray input = Bytes("input");
  const std::string hash = Hash(input);
  WriteBaseline(env, input, "baseline");
  const std::string path =
      (std::filesystem::path(DiffBaselineTestDir(env)) / hash).string();

  DiffBaselineStore store(env);
  EXPECT_THAT(store.Lookup(hash), Optional(Bytes("baseline")));
  EXPECT_EQ(store.Lookup(Hash(Bytes("other"))), std::nullopt);
  // Cached: removing the file does not change the result.
  std::filesystem::remove(path);
  EXPECT_THAT(store.Lookup(hash), Optional(Bytes("baseline")));
}

TEST_F(DiffBaselineTest, LookupAndSaveIoErrorsFailFinishDiffForTest) {
  // Read failure in validate mode: create a directory where a baseline file is
  // expected so reading it fails, and verify it is not cached as missing and
  // fails FinishDiffForTest.
  {
    const Environment env = EnvWithMode("validate");
    const ByteArray input = Bytes("input");
    const std::string hash = Hash(input);
    const std::string test_dir = DiffBaselineTestDir(env);
    std::filesystem::create_directories(std::filesystem::path(test_dir) / hash);
    StopCondition stop;
    PrepareDiffBaselineForTest(env, stop);
    ASSERT_FALSE(stop.StopRequested());

    DiffBaselineStore store(env);
    EXPECT_EQ(store.Lookup(hash), std::nullopt);
    EXPECT_EQ(DiffStats::Global().Get().io_errors, 1);
    FinishDiffForTest(env, stop);
    StopCondition::StopRequest request;
    ASSERT_TRUE(stop.StopRequested(&request));
    EXPECT_EQ(request.exit_code, EXIT_FAILURE);
  }
  // Write failure in record mode: occupy the baseline file path with a
  // directory so Save() fails, and verify FinishDiffForTest fails.
  {
    const Environment env = EnvWithMode("record");
    StopCondition stop;
    PrepareDiffBaselineForTest(env, stop);
    ASSERT_FALSE(stop.StopRequested());

    const ByteArray input = Bytes("input");
    const std::string hash = Hash(input);
    std::filesystem::create_directories(
        std::filesystem::path(DiffBaselineTestDir(env)) / hash);

    DiffBaselineStore store(env);
    const std::vector<ByteSpan> inputs = {input};
    const DiffBatch batch = store.PrepareBatch(inputs);
    BatchResult result;
    result.ClearAndResize(1);
    result.results()[0].metadata().cmp_data =
        EncodeDiffEnvelope(DiffEnvelopeKind::kRecords, {}, Bytes("rec"));
    result.num_outputs_read() = 1;
    store.ProcessBatchResult(batch, result);

    EXPECT_EQ(DiffStats::Global().Get().io_errors, 1);
    FinishDiffForTest(env, stop);
    StopCondition::StopRequest request;
    ASSERT_TRUE(stop.StopRequested(&request));
    EXPECT_EQ(request.exit_code, EXIT_FAILURE);
  }
}

TEST_F(DiffBaselineTest, ValidateWithoutBinaryDirectoryRequestsFailingStop) {
  const Environment env = EnvWithMode("validate");
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);
  StopCondition::StopRequest request;
  ASSERT_TRUE(stop.StopRequested(&request));
  EXPECT_EQ(request.exit_code, EXIT_FAILURE);
  // Validate never creates directories.
  EXPECT_FALSE(std::filesystem::exists(DiffBaselineBinaryDir(env)));
}

TEST_F(DiffBaselineTest, ValidateWithoutTestDirectoryOnlyWarns) {
  const Environment env = EnvWithMode("validate");
  std::filesystem::create_directories(DiffBaselineBinaryDir(env));
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);
  EXPECT_FALSE(stop.StopRequested());
  EXPECT_FALSE(std::filesystem::exists(DiffBaselineTestDir(env)));
}

TEST_F(DiffBaselineTest, ValidateSendsExpectationsOnlyForInputsWithBaseline) {
  const Environment env = EnvWithMode("validate");
  const ByteArray with = Bytes("with");
  const ByteArray without = Bytes("without");
  WriteBaseline(env, with, "expected");
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);  // Resets the stats.

  DiffBaselineStore store(env);
  const std::vector<ByteSpan> inputs = {with, without};
  const DiffBatch batch = store.PrepareBatch(inputs);
  ASSERT_EQ(batch.metadata.size(), 2);
  EXPECT_EQ(batch.hashes,
            (std::vector<std::string>{Hash(with), Hash(without)}));
  EXPECT_THAT(batch.metadata[1], IsEmpty());
  DiffEnvelopeKind kind;
  ByteSpan cmp;
  ByteSpan payload;
  ASSERT_TRUE(DecodeDiffEnvelope(batch.metadata[0], kind, cmp, payload));
  EXPECT_EQ(kind, DiffEnvelopeKind::kExpectations);
  EXPECT_THAT(cmp, IsEmpty());
  EXPECT_EQ(ByteArray(payload.begin(), payload.end()), Bytes("expected"));

  BatchResult result;
  result.ClearAndResize(2);
  result.results()[0].metadata().cmp_data =
      EncodeDiffEnvelope(DiffEnvelopeKind::kAck, {}, {});
  result.results()[1].metadata().cmp_data =
      EncodeDiffEnvelope(DiffEnvelopeKind::kAck, {}, {});
  result.num_outputs_read() = 2;
  store.ProcessBatchResult(batch, result);
  const DiffStats::Snapshot stats = DiffStats::Global().Get();
  EXPECT_EQ(stats.baselines_sent, 1);
  EXPECT_EQ(stats.baselines_acknowledged, 1);
  EXPECT_EQ(stats.baselines_missing, 1);
}

TEST_F(DiffBaselineTest,
       TruncatedBatchAndBatchTimeoutRecordIncompleteWithoutMisattributing) {
  const Environment env = EnvWithMode("validate");
  const ByteArray a = Bytes("a");
  const ByteArray b = Bytes("b");
  const ByteArray unsent = Bytes("unsent");
  for (const ByteArray* input : {&a, &b, &unsent}) {
    WriteBaseline(env, *input, "expected");
  }
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);
  DiffBaselineStore store(env);
  const std::vector<ByteSpan> inputs = {a, b, unsent};
  const DiffBatch batch = store.PrepareBatch(inputs);

  // Only 2 of the 3 inputs fit into inputs_blobseq_, and the batch timed out
  // after finishing input 0: neither `unsent` (not written) nor `b` (batch
  // timeout, not single-input crash) should be marked failed/sent improperly,
  // while `incomplete_batches` causes FinishDiffForTest to fail.
  BatchResult result;
  result.ClearAndResize(3);
  result.results()[0].metadata().cmp_data =
      EncodeDiffEnvelope(DiffEnvelopeKind::kAck, {}, {});
  result.num_outputs_read() = 1;
  result.exit_code() = EXIT_FAILURE;
  result.failure_description() = std::string(kExecutionFailurePerBatchTimeout);
  store.ProcessBatchResult(batch, result, /*num_inputs_written=*/2);

  const DiffStats::Snapshot stats = DiffStats::Global().Get();
  EXPECT_EQ(stats.baselines_sent, 2);
  EXPECT_EQ(stats.baselines_acknowledged, 1);
  EXPECT_EQ(stats.inputs_failed, 0);
  EXPECT_EQ(stats.incomplete_batches, 1);

  FinishDiffForTest(env, stop);
  EXPECT_TRUE(stop.StopRequested());
}

TEST_F(DiffBaselineTest, SetupFailureMarksBatchIncompleteNotSingleInputFailed) {
  const Environment env = EnvWithMode("validate");
  const ByteArray a = Bytes("a");
  WriteBaseline(env, a, "expected");
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);
  DiffBaselineStore store(env);
  const std::vector<ByteSpan> inputs = {a};
  const DiffBatch batch = store.PrepareBatch(inputs);

  BatchResult result;
  result.ClearAndResize(1);
  result.exit_code() = EXIT_FAILURE;
  result.failure_description() = "SETUP FAILURE: fixture failed";
  store.ProcessBatchResult(batch, result);

  const DiffStats::Snapshot stats = DiffStats::Global().Get();
  EXPECT_EQ(stats.inputs_failed, 0);
  EXPECT_EQ(stats.incomplete_batches, 1);
  FinishDiffForTest(env, stop);
  EXPECT_TRUE(stop.StopRequested());
}

TEST_F(DiffBaselineTest, SkippedTestDoesNotMarkBatchIncomplete) {
  const Environment env = EnvWithMode("validate");
  const ByteArray a = Bytes("a");
  WriteBaseline(env, a, "expected");
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);
  DiffBaselineStore store(env);
  const std::vector<ByteSpan> inputs = {a};
  const DiffBatch batch = store.PrepareBatch(inputs);

  BatchResult result;
  result.ClearAndResize(1);
  result.exit_code() = EXIT_FAILURE;
  result.failure_description() = "SKIPPED TEST: skipped";
  store.ProcessBatchResult(batch, result);

  const DiffStats::Snapshot stats = DiffStats::Global().Get();
  EXPECT_EQ(stats.inputs_failed, 0);
  EXPECT_EQ(stats.incomplete_batches, 0);
  FinishDiffForTest(env, stop);
  EXPECT_FALSE(stop.StopRequested());
}

TEST_F(DiffBaselineTest, RecordPersistsRecordsAndRestoresCmpData) {
  const Environment env = EnvWithMode("record");
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);
  DiffBaselineStore store(env);
  const ByteArray a = Bytes("a");
  const ByteArray b = Bytes("b");
  const ByteArray c = Bytes("c");
  const std::vector<ByteSpan> inputs = {a, b, c};
  const DiffBatch batch = store.PrepareBatch(inputs);
  EXPECT_THAT(batch.metadata, IsEmpty());  // Record allocates no metadata.

  BatchResult result;
  result.ClearAndResize(3);
  result.results()[0].metadata().cmp_data =
      EncodeDiffEnvelope(DiffEnvelopeKind::kRecords, {5}, Bytes("rec-a"));
  result.results()[1].metadata().cmp_data =
      EncodeDiffEnvelope(DiffEnvelopeKind::kSkippedUnparsable, {}, {});
  // Input c crashed: not read.
  result.num_outputs_read() = 2;
  result.exit_code() = EXIT_FAILURE;
  result.failure_description() = "SIGSEGV";
  store.ProcessBatchResult(batch, result);

  EXPECT_EQ(result.results()[0].metadata().cmp_data, ByteArray{5});
  EXPECT_THAT(result.results()[1].metadata().cmp_data, IsEmpty());
  const std::string test_dir = DiffBaselineTestDir(env);
  EXPECT_EQ(ReadFileOrDie((std::filesystem::path(test_dir) / Hash(a)).string()),
            "rec-a");
  EXPECT_FALSE(
      std::filesystem::exists(std::filesystem::path(test_dir) / Hash(b)));
  EXPECT_FALSE(
      std::filesystem::exists(std::filesystem::path(test_dir) / Hash(c)));
  const DiffStats::Snapshot stats = DiffStats::Global().Get();
  EXPECT_EQ(stats.executions, 2);
  EXPECT_EQ(stats.baselines_written, 1);
  EXPECT_EQ(stats.inputs_unparsable, 1);
  EXPECT_EQ(stats.inputs_failed, 1);
  EXPECT_EQ(stats.mismatches, 0);

  // A record run with failed inputs fails at the end.
  FinishDiffForTest(env, stop);
  StopCondition::StopRequest request;
  ASSERT_TRUE(stop.StopRequested(&request));
  EXPECT_EQ(request.exit_code, EXIT_FAILURE);
}

TEST_F(DiffBaselineTest, CleanRecordDoesNotFail) {
  const Environment env = EnvWithMode("record");
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);
  DiffBaselineStore store(env);
  const ByteArray a = Bytes("a");
  const std::vector<ByteSpan> inputs = {a};
  const DiffBatch batch = store.PrepareBatch(inputs);
  BatchResult result;
  result.ClearAndResize(1);
  result.results()[0].metadata().cmp_data =
      EncodeDiffEnvelope(DiffEnvelopeKind::kRecords, {}, Bytes("rec-a"));
  result.num_outputs_read() = 1;
  store.ProcessBatchResult(batch, result);
  FinishDiffForTest(env, stop);
  EXPECT_FALSE(stop.StopRequested());
}

TEST_F(DiffBaselineTest, ValidateCountsAcksMismatchesAndFailsAtTheEnd) {
  const Environment env = EnvWithMode("validate");
  const ByteArray ok = Bytes("ok");
  const ByteArray bad = Bytes("bad");
  const ByteArray after = Bytes("after");
  for (const ByteArray* input : {&ok, &bad, &after}) {
    WriteBaseline(env, *input, "expected");
  }
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);
  ASSERT_FALSE(stop.StopRequested());
  DiffBaselineStore store(env);
  const std::vector<ByteSpan> inputs = {ok, bad, after};
  const DiffBatch batch = store.PrepareBatch(inputs);
  BatchResult result;
  result.ClearAndResize(3);
  result.results()[0].metadata().cmp_data =
      EncodeDiffEnvelope(DiffEnvelopeKind::kAck, {}, {});
  result.num_outputs_read() = 1;
  result.exit_code() = EXIT_FAILURE;
  result.failure_description() = "RecordOrDiff mismatch";
  store.ProcessBatchResult(batch, result);

  DiffStats::Snapshot stats = DiffStats::Global().Get();
  EXPECT_EQ(stats.baselines_sent, 3);
  EXPECT_EQ(stats.baselines_acknowledged, 1);
  EXPECT_EQ(stats.inputs_failed, 1);
  EXPECT_EQ(stats.mismatches, 1);

  // The same mismatching input re-executed alone (e.g. by ReportCrash) is
  // counted once.
  const std::vector<ByteSpan> single = {bad};
  const DiffBatch single_batch = store.PrepareBatch(single);
  BatchResult single_result;
  single_result.ClearAndResize(1);
  single_result.exit_code() = EXIT_FAILURE;
  single_result.failure_description() = "RecordOrDiff mismatch";
  store.ProcessBatchResult(single_batch, single_result);
  stats = DiffStats::Global().Get();
  EXPECT_EQ(stats.mismatches, 1);
  EXPECT_EQ(stats.inputs_failed, 1);

  FinishDiffForTest(env, stop);
  StopCondition::StopRequest request;
  ASSERT_TRUE(stop.StopRequested(&request));
  EXPECT_EQ(request.exit_code, EXIT_FAILURE);
}

TEST_F(DiffBaselineTest, ValidateFailsForUnparsableInputsWithBaseline) {
  const Environment env = EnvWithMode("validate");
  const ByteArray input = Bytes("input");
  WriteBaseline(env, input, "expected");
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);
  DiffBaselineStore store(env);
  const std::vector<ByteSpan> inputs = {input};
  const DiffBatch batch = store.PrepareBatch(inputs);
  BatchResult result;
  result.ClearAndResize(1);
  result.results()[0].metadata().cmp_data =
      EncodeDiffEnvelope(DiffEnvelopeKind::kSkippedUnparsable, {}, {});
  result.num_outputs_read() = 1;
  store.ProcessBatchResult(batch, result);
  const DiffStats::Snapshot stats = DiffStats::Global().Get();
  EXPECT_EQ(stats.inputs_unparsable, 1);
  EXPECT_EQ(stats.unparsable_with_baseline, 1);
  FinishDiffForTest(env, stop);
  EXPECT_TRUE(stop.StopRequested());
}

TEST_F(DiffBaselineTest, ValidateAllowsUnparsableInputsWithoutBaseline) {
  const Environment env = EnvWithMode("validate");
  std::filesystem::create_directories(DiffBaselineTestDir(env));
  const ByteArray input = Bytes("unparsable_new_input");
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);
  DiffBaselineStore store(env);
  const std::vector<ByteSpan> inputs = {input};
  const DiffBatch batch = store.PrepareBatch(inputs);
  BatchResult result;
  result.ClearAndResize(1);
  result.results()[0].metadata().cmp_data =
      EncodeDiffEnvelope(DiffEnvelopeKind::kSkippedUnparsable, {}, {});
  result.num_outputs_read() = 1;
  store.ProcessBatchResult(batch, result);
  const DiffStats::Snapshot stats = DiffStats::Global().Get();
  EXPECT_EQ(stats.inputs_unparsable, 1);
  EXPECT_EQ(stats.unparsable_with_baseline, 0);
  FinishDiffForTest(env, stop);
  EXPECT_FALSE(stop.StopRequested());
}

TEST_F(DiffBaselineTest, CleanValidatePasses) {
  const Environment env = EnvWithMode("validate");
  const ByteArray a = Bytes("a");
  WriteBaseline(env, a, "expected");
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);
  DiffBaselineStore store(env);
  const std::vector<ByteSpan> inputs = {a};
  const DiffBatch batch = store.PrepareBatch(inputs);
  BatchResult result;
  result.ClearAndResize(1);
  result.results()[0].metadata().cmp_data =
      EncodeDiffEnvelope(DiffEnvelopeKind::kAck, {}, {});
  result.num_outputs_read() = 1;
  store.ProcessBatchResult(batch, result);
  FinishDiffForTest(env, stop);
  EXPECT_FALSE(stop.StopRequested());
}

TEST_F(DiffBaselineTest,
       ResultsWithoutEnvelopeOrWithExpectationsEnvelopeAreLeftUntouched) {
  const Environment env = EnvWithMode("validate");
  std::filesystem::create_directories(DiffBaselineTestDir(env));
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);
  DiffBaselineStore store(env);
  const ByteArray a = Bytes("a");
  const ByteArray b = Bytes("b");
  const std::vector<ByteSpan> inputs = {a, b};
  const DiffBatch batch = store.PrepareBatch(inputs);
  const ByteArray expectations_env = EncodeDiffEnvelope(
      DiffEnvelopeKind::kExpectations, {9}, Bytes("unexpected"));
  BatchResult result;
  result.ClearAndResize(2);
  result.results()[0].metadata().cmp_data = {2, 1, 2, 3, 4};
  result.results()[1].metadata().cmp_data = expectations_env;
  result.num_outputs_read() = 2;
  store.ProcessBatchResult(batch, result);
  EXPECT_EQ(result.results()[0].metadata().cmp_data,
            (ByteArray{2, 1, 2, 3, 4}));
  EXPECT_EQ(result.results()[1].metadata().cmp_data, expectations_env);
  EXPECT_EQ(DiffStats::Global().Get().executions, 0);
}

TEST_F(DiffBaselineTest, InactiveDoesNothing) {
  const Environment env = EnvWithMode("");
  StopCondition stop;
  PrepareDiffBaselineForTest(env, stop);
  FinishDiffForTest(env, stop);
  EXPECT_FALSE(stop.StopRequested());
  EXPECT_FALSE(std::filesystem::exists(root_.path() / "baseline"));
}

}  // namespace
}  // namespace fuzztest::internal
