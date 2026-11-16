// Copyright 2026 Google LLC
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

#include "./fuzztest/record_or_diff.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/functional/function_ref.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/internal/configuration.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/runtime.h"
#include "./fuzztest/internal/serialization.h"

namespace fuzztest {
namespace {

using ::fuzztest::internal::DecodeDiffRecordContainer;
using ::fuzztest::internal::DiffMode;
using ::fuzztest::internal::DiffRecord;
using ::fuzztest::internal::EncodeDiffRecordContainer;
using ::fuzztest::internal::Runtime;
using ::fuzztest::internal::RuntimeDiffResult;
using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::Optional;

struct Quote {
  int64_t total_cents;
  int discount_pct;
  friend bool operator==(const Quote& a, const Quote& b) {
    return a.total_cents == b.total_cents && a.discount_pct == b.discount_pct;
  }
};

// An aggregate without operator==.
struct NoEq {
  int x;
};

// Minimal fake satisfying `internal::is_protocol_buffer_v<FakeProto>` without
// pulling in full protobuf runtime dependencies.
struct FakeProto {
  struct Field {};
  struct Descriptor {
    const Field* field(int) const { return nullptr; }
  };
  struct Reflection {
    bool HasField(const FakeProto&, const Field*) const { return false; }
  };
  using Message = FakeProto;
  const Descriptor* GetDescriptor() const { return nullptr; }
  const Reflection* GetReflection() const { return nullptr; }
};

// A non-aggregate class that `Arbitrary<T>()` cannot handle.
class Opaque {
 public:
  explicit Opaque(int v) : v_(v) {}
  int v() const { return v_; }
  friend bool operator==(const Opaque& a, const Opaque& b) {
    return a.v_ == b.v_;
  }

 private:
  int v_;
};

enum class Color : int16_t { kRed = 7, kBlue = -3 };

DiffCodec<Opaque> OpaqueCodec() {
  DiffCodec<Opaque> codec;
  codec.serializer = [](const Opaque& o) { return absl::StrCat("v=", o.v()); };
  codec.deserializer = [](std::string_view s) -> std::optional<Opaque> {
    int v;
    if (s.size() < 2 || s.substr(0, 2) != "v=" ||
        !absl::SimpleAtoi(s.substr(2), &v)) {
      return std::nullopt;
    }
    return Opaque(v);
  };
  return codec;
}

template <typename T>
std::optional<T> RoundTripDefaultDeserialize(absl::string_view bytes) {
  std::optional<T> decoded;
  if (!internal::DefaultDiffWithDeserialized<T>(
          bytes, [&](const T& v) { decoded = v; })) {
    return std::nullopt;
  }
  return decoded;
}

class RecordOrDiffTest : public ::testing::Test {
 protected:
  struct DiffRun {
    RuntimeDiffResult::Kind kind = RuntimeDiffResult::Kind::kAck;
    std::string container;
    std::optional<std::string> crash_type;
    std::string stderr_output;
  };

  void TearDown() override {
    runtime().DisableDiffMode();
    runtime().ResetCrashType();
    runtime().SetExternalFailureDetected(false);
  }

  static Runtime& runtime() { return Runtime::instance(); }

  DiffRun RunDiffInput(DiffMode mode,
                       std::optional<std::string> expected_container,
                       absl::FunctionRef<void()> body, bool unparsable) {
    DiffRun run;
    runtime().EnableDiffMode(mode);
    runtime().BeginDiffInput(std::move(expected_container), unparsable);
    ::testing::internal::CaptureStderr();
    body();
    runtime().CheckDiffRecordsAtInputEnd();
    run.stderr_output = ::testing::internal::GetCapturedStderr();
    run.crash_type = runtime().crash_type();
    std::optional<RuntimeDiffResult> result = runtime().TakeDiffResult();
    runtime().DisableDiffMode();
    runtime().ResetCrashType();
    runtime().SetExternalFailureDetected(false);
    EXPECT_TRUE(result.has_value());
    if (result.has_value()) {
      run.kind = result->kind;
      run.container = std::move(result->container);
    }
    return run;
  }

  // Runs `body` as one input in record mode and returns the run outcome.
  DiffRun RecordOutcome(absl::FunctionRef<void()> body,
                        bool unparsable = false) {
    return RunDiffInput(DiffMode::kRecord, std::nullopt, body, unparsable);
  }

  std::string Record(absl::FunctionRef<void()> body, bool unparsable = false) {
    DiffRun run = RecordOutcome(body, unparsable);
    EXPECT_EQ(run.crash_type, std::nullopt);
    return run.container;
  }

  // Runs `body` as one input in validate mode against `container` and returns
  // the run outcome.
  DiffRun ValidateOutcome(std::optional<std::string> container,
                          absl::FunctionRef<void()> body,
                          bool unparsable = false) {
    return RunDiffInput(DiffMode::kValidate, std::move(container), body,
                        unparsable);
  }

  static int CountOccurrences(std::string_view haystack,
                              std::string_view needle) {
    int count = 0;
    for (size_t pos = haystack.find(needle); pos != haystack.npos;
         pos = haystack.find(needle, pos + needle.size())) {
      ++count;
    }
    return count;
  }
};

TEST(DiffRecordContainerTest, RoundTripsSortedAndDeterministic) {
  const std::string a = EncodeDiffRecordContainer(
      {{"b", "2"}, {"a", std::string("\0x", 2)}, {"", ""}});
  const std::string b = EncodeDiffRecordContainer(
      {{"", ""}, {"a", std::string("\0x", 2)}, {"b", "2"}});
  EXPECT_EQ(a, b);
  EXPECT_THAT(DecodeDiffRecordContainer(a),
              Optional(ElementsAre(DiffRecord{"", ""},
                                   DiffRecord{"a", std::string("\0x", 2)},
                                   DiffRecord{"b", "2"})));
}

TEST(DiffRecordContainerTest, EmptyContainerIsValid) {
  EXPECT_THAT(DecodeDiffRecordContainer(EncodeDiffRecordContainer({})),
              Optional(ElementsAre()));
}

TEST(DiffRecordContainerTest, RejectsMalformedContainers) {
  EXPECT_EQ(DecodeDiffRecordContainer("garbage"), std::nullopt);
  EXPECT_EQ(DecodeDiffRecordContainer(""), std::nullopt);
  // Duplicate labels.
  internal::IRObject obj;
  auto& subs = obj.MutableSubs();
  subs.emplace_back(uint64_t{1});
  internal::IRObject list;
  for (int i = 0; i < 2; ++i) {
    internal::IRObject entry;
    entry.MutableSubs().emplace_back(internal::IRObject::Value("x"));
    entry.MutableSubs().emplace_back(internal::IRObject::Value("p"));
    list.MutableSubs().push_back(entry);
  }
  subs.push_back(list);
  EXPECT_EQ(DecodeDiffRecordContainer(internal::SerializeIRObject(obj)),
            std::nullopt);
  // Unsupported version.
  subs[0] = internal::IRObject(uint64_t{2});
  subs[1] = internal::IRObject();
  EXPECT_EQ(DecodeDiffRecordContainer(internal::SerializeIRObject(obj)),
            std::nullopt);
  // Non-string (monostate) label/payload.
  subs[0] = internal::IRObject(uint64_t{1});
  internal::IRObject empty_entry_list;
  internal::IRObject empty_entry;
  empty_entry.MutableSubs().resize(2);
  empty_entry_list.MutableSubs().push_back(std::move(empty_entry));
  subs[1] = std::move(empty_entry_list);
  EXPECT_EQ(DecodeDiffRecordContainer(internal::SerializeIRObject(obj)),
            std::nullopt);
}

TEST_F(RecordOrDiffTest, InactiveIsNoOp) {
  ASSERT_FALSE(runtime().diff_active());
  RecordOrDiff(42, "x");
  RecordOrDiff(42, "x");  // A duplicate label is not detected when inactive.
  EXPECT_EQ(runtime().crash_type(), std::nullopt);
  EXPECT_EQ(runtime().TakeDiffResult(), std::nullopt);
}

TEST_F(RecordOrDiffTest, TakeDiffResultIsNulloptWithoutBeginDiffInput) {
  runtime().EnableDiffMode(DiffMode::kRecord);
  EXPECT_EQ(runtime().TakeDiffResult(), std::nullopt);
  runtime().BeginDiffInput(std::nullopt, /*unparsable=*/false);
  EXPECT_NE(runtime().TakeDiffResult(), std::nullopt);
  // Consumed: a second take (e.g. for an input that was not executed) yields
  // nothing.
  EXPECT_EQ(runtime().TakeDiffResult(), std::nullopt);
}

TEST_F(RecordOrDiffTest, CallsBeforeBeginDiffInputAreIgnoredWithoutPoisoning) {
  runtime().EnableDiffMode(DiffMode::kRecord);
  EXPECT_TRUE(runtime().ShouldSkipDiffCall());
  RecordOrDiff(10, "setup");
  RecordOrDiff(10, "setup");  // Duplicate before BeginDiffInput is ignored.
  DiffCodec<Opaque> bad_codec;
  RecordOrDiffOptions<Opaque> bad_options;
  bad_options.label = "setup_codec";
  RecordOrDiff(Opaque(1), bad_codec, bad_options);
  EXPECT_EQ(runtime().crash_type(), std::nullopt);

  // Subsequent input execution can still claim "setup" cleanly.
  runtime().BeginDiffInput(std::nullopt, /*unparsable=*/false);
  RecordOrDiff(99, "setup");
  runtime().CheckDiffRecordsAtInputEnd();
  EXPECT_EQ(runtime().crash_type(), std::nullopt);
  std::optional<RuntimeDiffResult> result = runtime().TakeDiffResult();
  ASSERT_TRUE(result.has_value());
  auto records = DecodeDiffRecordContainer(result->container);
  ASSERT_TRUE(records.has_value());
  ASSERT_EQ(records->size(), 1);
  EXPECT_EQ((*records)[0].label, "setup");
  EXPECT_THAT(RoundTripDefaultDeserialize<int>((*records)[0].payload),
              Optional(99));
}

TEST_F(RecordOrDiffTest, SingleUnlabeledCallIsRecordedUnderEmptyLabel) {
  const DiffRun rec = RecordOutcome([] { RecordOrDiff(42); });
  EXPECT_EQ(rec.kind, RuntimeDiffResult::Kind::kRecords);
  EXPECT_EQ(rec.crash_type, std::nullopt);
  auto records = DecodeDiffRecordContainer(rec.container);
  ASSERT_TRUE(records.has_value());
  ASSERT_EQ(records->size(), 1);
  EXPECT_EQ((*records)[0].label, "");
  EXPECT_THAT(RoundTripDefaultDeserialize<int>((*records)[0].payload),
              Optional(42));
  // And it validates.
  const DiffRun val = ValidateOutcome(rec.container, [] { RecordOrDiff(42); });
  EXPECT_EQ(val.crash_type, std::nullopt);
  EXPECT_THAT(val.stderr_output, Not(HasSubstr("RecordOrDiff MISMATCH")));
  EXPECT_EQ(val.kind, RuntimeDiffResult::Kind::kAck);
}

TEST_F(RecordOrDiffTest, DuplicateLabelFailsInRecord) {
  const DiffRun rec = RecordOutcome([] {
    RecordOrDiff(1, "x");
    RecordOrDiff(2, "x");
    RecordOrDiff(3, "y");
  });
  EXPECT_THAT(
      rec.crash_type,
      Optional(std::string("RecordOrDiff usage error: duplicate label")));
  EXPECT_THAT(rec.stderr_output,
              HasSubstr("RecordOrDiff label \"x\" used twice in one "
                        "input; give each call a distinct label"));
}

TEST_F(RecordOrDiffTest, TwoUnlabeledCallsAreADuplicate) {
  const DiffRun rec = RecordOutcome([] {
    RecordOrDiff(1);
    RecordOrDiff(2);
  });
  EXPECT_THAT(
      rec.crash_type,
      Optional(std::string("RecordOrDiff usage error: duplicate label")));
  EXPECT_THAT(rec.stderr_output,
              HasSubstr("RecordOrDiff label \"\" used twice"));
}

TEST_F(RecordOrDiffTest, DuplicateLabelFailsInValidate) {
  const std::string container = Record([] { RecordOrDiff(1, "x"); });
  const DiffRun val = ValidateOutcome(container, [] {
    RecordOrDiff(1, "x");
    RecordOrDiff(1, "x");
  });
  EXPECT_THAT(
      val.crash_type,
      Optional(std::string("RecordOrDiff usage error: duplicate label")));
  EXPECT_THAT(val.stderr_output,
              HasSubstr("RecordOrDiff label \"x\" used twice"));
  // The usage error is the only finding of the input.
  EXPECT_THAT(val.stderr_output, Not(HasSubstr("=== RecordOrDiff MISMATCH")));
}

TEST_F(RecordOrDiffTest, DuplicateLabelFailsInValidateWithoutBaseline) {
  const DiffRun val = ValidateOutcome(std::nullopt, [] {
    RecordOrDiff(1, "x");
    RecordOrDiff(2, "x");
  });
  EXPECT_THAT(
      val.crash_type,
      Optional(std::string("RecordOrDiff usage error: duplicate label")));
}

TEST_F(RecordOrDiffTest, LabelsInLoopsAreUnique) {
  const std::string container = Record([] {
    for (int i = 0; i < 3; ++i) RecordOrDiff(i * 10, absl::StrCat("item/", i));
  });
  auto records = DecodeDiffRecordContainer(container);
  ASSERT_TRUE(records.has_value());
  EXPECT_EQ(records->size(), 3);
}

TEST_F(RecordOrDiffTest, ReorderedCallsPass) {
  const std::string container = Record([] {
    RecordOrDiff(1, "a");
    RecordOrDiff(std::string("two"), "b");
    RecordOrDiff(Quote{300, 10}, "c");
  });
  const DiffRun val = ValidateOutcome(container, [] {
    RecordOrDiff(Quote{300, 10}, "c");
    RecordOrDiff(1, "a");
    RecordOrDiff(std::string("two"), "b");
  });
  EXPECT_EQ(val.crash_type, std::nullopt);
  EXPECT_THAT(val.stderr_output, Not(HasSubstr("RecordOrDiff MISMATCH")));
}

TEST_F(RecordOrDiffTest, ValueDiffersIsReportedWithLabelAndValues) {
  const std::string container = Record([] {
    RecordOrDiff(Quote{1000, 10}, "quote");
    RecordOrDiff(std::string("same"), "s");
  });
  const DiffRun val = ValidateOutcome(container, [] {
    RecordOrDiff(Quote{1100, 11}, "quote");
    RecordOrDiff(std::string("same"), "s");
  });
  EXPECT_THAT(val.crash_type, Optional(std::string("RecordOrDiff mismatch")));
  EXPECT_THAT(val.stderr_output, HasSubstr("=== RecordOrDiff MISMATCH"));
  EXPECT_THAT(val.stderr_output, HasSubstr("Mismatched outputs: 1\n"));
  EXPECT_THAT(val.stderr_output, HasSubstr("--- RecordOrDiff label: quote\n"
                                           "Reason: value differs\n"
                                           "Expected (baseline): "));
  EXPECT_THAT(val.stderr_output, HasSubstr("1000"));
  EXPECT_THAT(val.stderr_output, HasSubstr("1100"));
  EXPECT_THAT(val.stderr_output, Not(HasSubstr("--- RecordOrDiff label: s\n")));
}

TEST_F(RecordOrDiffTest, NewLabelIsReported) {
  const std::string container = Record([] { RecordOrDiff(1, "a"); });
  const DiffRun val = ValidateOutcome(container, [] {
    RecordOrDiff(1, "a");
    RecordOrDiff(5, "extra");
  });
  EXPECT_THAT(val.crash_type, Optional(std::string("RecordOrDiff mismatch")));
  EXPECT_THAT(val.stderr_output,
              HasSubstr("--- RecordOrDiff label: extra\n"
                        "Reason: new output \"extra\" not in baseline\n"
                        "Expected (baseline): <no output>\n"
                        "Actual (current): 5\n"));
}

TEST_F(RecordOrDiffTest, MissingLabelIsReportedAtInputEnd) {
  const std::string container = Record([] {
    RecordOrDiff(1, "a");
    RecordOrDiff(2, "gone");
  });
  const DiffRun val = ValidateOutcome(container, [] { RecordOrDiff(1, "a"); });
  EXPECT_THAT(val.crash_type, Optional(std::string("RecordOrDiff mismatch")));
  EXPECT_THAT(val.stderr_output,
              HasSubstr("--- RecordOrDiff label: gone\n"
                        "Reason: baseline output \"gone\" was not "
                        "produced\n"));
  EXPECT_THAT(val.stderr_output, HasSubstr("Actual (current): <no output>\n"));
}

TEST_F(RecordOrDiffTest, UnlabeledMismatchIsShownAsUnlabeled) {
  const std::string container = Record([] { RecordOrDiff(1); });
  const DiffRun val = ValidateOutcome(container, [] { RecordOrDiff(2); });
  EXPECT_THAT(val.stderr_output,
              HasSubstr("--- RecordOrDiff label: <unlabeled>\n"
                        "Reason: value differs\n"
                        "Expected (baseline): 1\n"
                        "Actual (current): 2\n"));
}

TEST_F(RecordOrDiffTest, AllMismatchesAreReportedOnceSortedByLabel) {
  const std::string container = Record([] {
    RecordOrDiff(1, "b");
    RecordOrDiff(2, "a");
    RecordOrDiff(3, "c");
  });
  const DiffRun val = ValidateOutcome(container, [] {
    RecordOrDiff(20, "a");
    RecordOrDiff(10, "b");
    RecordOrDiff(4, "d");
  });
  EXPECT_EQ(CountOccurrences(val.stderr_output, "=== RecordOrDiff MISMATCH"),
            1);
  EXPECT_THAT(val.stderr_output, HasSubstr("Mismatched outputs: 4\n"));
  const size_t a = val.stderr_output.find("--- RecordOrDiff label: a\n");
  const size_t b = val.stderr_output.find("--- RecordOrDiff label: b\n");
  const size_t c = val.stderr_output.find("--- RecordOrDiff label: c\n");
  const size_t d = val.stderr_output.find("--- RecordOrDiff label: d\n");
  ASSERT_NE(a, std::string::npos);
  ASSERT_NE(b, std::string::npos);
  ASSERT_NE(c, std::string::npos);
  ASSERT_NE(d, std::string::npos);
  EXPECT_LT(a, b);
  EXPECT_LT(b, c);
  EXPECT_LT(c, d);
  EXPECT_THAT(val.crash_type, Optional(std::string("RecordOrDiff mismatch")));
}

TEST_F(RecordOrDiffTest, MissingBaselineComparesNothing) {
  const DiffRun val =
      ValidateOutcome(std::nullopt, [] { RecordOrDiff(1, "a"); });
  EXPECT_EQ(val.crash_type, std::nullopt);
  EXPECT_THAT(val.stderr_output, Not(HasSubstr("RecordOrDiff MISMATCH")));
  EXPECT_EQ(val.kind, RuntimeDiffResult::Kind::kAck);
}

TEST_F(RecordOrDiffTest, UndecodableContainerIsReported) {
  const DiffRun val = ValidateOutcome(std::string("not a container"),
                                      [] { RecordOrDiff(1, "a"); });
  EXPECT_THAT(val.crash_type, Optional(std::string("RecordOrDiff mismatch")));
  EXPECT_THAT(val.stderr_output,
              HasSubstr("--- RecordOrDiff label: <baseline container>\n"
                        "Reason: cannot decode baseline container\n"
                        "Expected (baseline): <undecodable: 15 bytes>\n"));
}

TEST_F(RecordOrDiffTest, UndecodableValueIsReported) {
  const std::string container = EncodeDiffRecordContainer({{"a", "garbage"}});
  const DiffRun val = ValidateOutcome(container, [] { RecordOrDiff(1, "a"); });
  EXPECT_THAT(val.stderr_output,
              HasSubstr("Reason: cannot decode baseline value\n"
                        "Expected (baseline): <undecodable: 7 bytes>\n"
                        "Actual (current): 1\n"));
}

TEST_F(RecordOrDiffTest, UnparsableInputIsSkippedInBothModes) {
  const DiffRun rec = RecordOutcome(
      [] {
        RecordOrDiff(1, "a");
        RecordOrDiff(1, "a");  // Not even a duplicate: the input is skipped.
      },
      /*unparsable=*/true);
  EXPECT_EQ(rec.kind, RuntimeDiffResult::Kind::kSkippedUnparsable);
  EXPECT_EQ(rec.container, "");
  EXPECT_EQ(rec.crash_type, std::nullopt);

  const std::string baseline = EncodeDiffRecordContainer({{"a", "x"}});
  const DiffRun val = ValidateOutcome(
      baseline, [] { RecordOrDiff(2, "b"); }, /*unparsable=*/true);
  EXPECT_EQ(val.kind, RuntimeDiffResult::Kind::kSkippedUnparsable);
  EXPECT_EQ(val.crash_type, std::nullopt);
  EXPECT_THAT(val.stderr_output, Not(HasSubstr("RecordOrDiff MISMATCH")));
}

TEST_F(RecordOrDiffTest, TopLevelEnumIsEncodedByValue) {
  const std::string container =
      Record([] { RecordOrDiff(Color::kBlue, "color"); });
  auto records = DecodeDiffRecordContainer(container);
  ASSERT_TRUE(records.has_value());
  ASSERT_EQ(records->size(), 1);
  auto obj = internal::ParseIRObject((*records)[0].payload);
  ASSERT_TRUE(obj.has_value());
  EXPECT_THAT(obj->GetScalar<Color>(), Optional(Color::kBlue));
  EXPECT_THAT(RoundTripDefaultDeserialize<Color>((*records)[0].payload),
              Optional(Color::kBlue));
  const DiffRun val =
      ValidateOutcome(container, [] { RecordOrDiff(Color::kRed, "color"); });
  EXPECT_THAT(val.stderr_output, HasSubstr("(-3)"));
  EXPECT_THAT(val.stderr_output, HasSubstr("(7)"));
}

TEST_F(RecordOrDiffTest, NanEqualsNanForFloatingPoint) {
  const std::string container = Record(
      [] { RecordOrDiff(std::numeric_limits<double>::quiet_NaN(), "nan"); });
  const DiffRun val = ValidateOutcome(container, [] {
    RecordOrDiff(std::numeric_limits<double>::quiet_NaN(), "nan");
  });
  EXPECT_EQ(val.crash_type, std::nullopt);
}

TEST_F(RecordOrDiffTest, NanVersusFiniteFloatingPointIsMismatch) {
  const std::string container = Record(
      [] { RecordOrDiff(std::numeric_limits<double>::quiet_NaN(), "nan"); });
  const DiffRun val =
      ValidateOutcome(container, [] { RecordOrDiff(0.0, "nan"); });
  EXPECT_THAT(val.crash_type, Optional(std::string("RecordOrDiff mismatch")));
  EXPECT_THAT(val.stderr_output, HasSubstr("--- RecordOrDiff label: nan\n"
                                           "Reason: value differs\n"));
}

TEST_F(RecordOrDiffTest, MissingComparatorIsAUsageError) {
  const DiffRun rec = RecordOutcome([] { RecordOrDiff(NoEq{1}, "noeq"); });
  EXPECT_THAT(
      rec.crash_type,
      Optional(std::string("RecordOrDiff usage error: missing comparator")));
  EXPECT_THAT(rec.stderr_output, HasSubstr("has no operator==; pass "
                                           "RecordOrDiffOptions::comparator"));
  EXPECT_THAT(rec.stderr_output, Not(HasSubstr("MessageDifferencer::Equals")));
}

TEST_F(RecordOrDiffTest,
       MissingComparatorOnProtoTypeSuggestsMessageDifferencer) {
  static_assert(internal::is_protocol_buffer_v<FakeProto>);
  DiffCodec<FakeProto> codec;
  codec.serializer = [](const FakeProto&) { return std::string(); };
  codec.deserializer = [](std::string_view) -> std::optional<FakeProto> {
    return FakeProto{};
  };
  RecordOrDiffOptions<FakeProto> options;
  options.label = "proto";
  const DiffRun rec =
      RecordOutcome([&] { RecordOrDiff(FakeProto{}, codec, options); });
  EXPECT_THAT(
      rec.crash_type,
      Optional(std::string("RecordOrDiff usage error: missing comparator")));
  EXPECT_THAT(rec.stderr_output, HasSubstr("MessageDifferencer::Equals"));
}

TEST_F(RecordOrDiffTest, CustomComparatorAcceptsEquivalentValues) {
  RecordOrDiffOptions<NoEq> options;
  options.label = "noeq";
  options.comparator = [](const NoEq& a, const NoEq& b) {
    return a.x % 2 == b.x % 2;
  };
  const std::string container = Record([&] { RecordOrDiff(NoEq{1}, options); });
  const DiffRun val =
      ValidateOutcome(container, [&] { RecordOrDiff(NoEq{3}, options); });
  EXPECT_EQ(val.crash_type, std::nullopt);
}

TEST_F(RecordOrDiffTest, CustomComparatorReportsNonEquivalentValues) {
  RecordOrDiffOptions<NoEq> options;
  options.label = "noeq";
  options.comparator = [](const NoEq& a, const NoEq& b) {
    return a.x % 2 == b.x % 2;
  };
  const std::string container = Record([&] { RecordOrDiff(NoEq{1}, options); });
  const DiffRun val =
      ValidateOutcome(container, [&] { RecordOrDiff(NoEq{2}, options); });
  EXPECT_THAT(val.crash_type, Optional(std::string("RecordOrDiff mismatch")));
}

TEST_F(RecordOrDiffTest, CustomPrinterIsUsed) {
  RecordOrDiffOptions<int> options;
  options.label = "p";
  options.printer = [](const int& v) { return absl::StrCat("<<", v, ">>"); };
  const std::string container = Record([&] { RecordOrDiff(1, options); });
  const DiffRun val =
      ValidateOutcome(container, [&] { RecordOrDiff(2, options); });
  EXPECT_THAT(val.stderr_output, HasSubstr("Expected (baseline): <<1>>\n"
                                           "Actual (current): <<2>>\n"));
}

TEST_F(RecordOrDiffTest, CodecPathRecordsAndValidatesMatchingBytes) {
  RecordOrDiffOptions<Opaque> options;
  options.label = "o";
  const std::string container =
      Record([&] { RecordOrDiff(Opaque(5), OpaqueCodec(), options); });
  EXPECT_THAT(DecodeDiffRecordContainer(container),
              Optional(ElementsAre(DiffRecord{"o", "v=5"})));
  const DiffRun val = ValidateOutcome(
      container, [&] { RecordOrDiff(Opaque(5), OpaqueCodec(), options); });
  EXPECT_EQ(val.crash_type, std::nullopt);
}

TEST_F(RecordOrDiffTest, CodecPathReportsEscapedBytesOnMismatch) {
  RecordOrDiffOptions<Opaque> options;
  options.label = "o";
  const std::string container =
      Record([&] { RecordOrDiff(Opaque(5), OpaqueCodec(), options); });
  const DiffRun val = ValidateOutcome(
      container, [&] { RecordOrDiff(Opaque(6), OpaqueCodec(), options); });
  EXPECT_THAT(val.crash_type, Optional(std::string("RecordOrDiff mismatch")));
  EXPECT_THAT(val.stderr_output, HasSubstr("Expected (baseline): \"v=5\"\n"
                                           "Actual (current): \"v=6\"\n"));
}

TEST_F(RecordOrDiffTest, CodecWithNullSerializerReportsInvalidCodec) {
  DiffCodec<Opaque> codec = OpaqueCodec();
  codec.serializer = nullptr;
  RecordOrDiffOptions<Opaque> options;
  options.label = "bad_ser";
  const DiffRun rec =
      RecordOutcome([&] { RecordOrDiff(Opaque(1), codec, options); });
  EXPECT_THAT(rec.crash_type,
              Optional(std::string("RecordOrDiff usage error: invalid codec")));
  EXPECT_THAT(rec.stderr_output,
              HasSubstr("for label \"bad_ser\" must have both a serializer and "
                        "a deserializer"));
}

TEST_F(RecordOrDiffTest, CodecWithNullDeserializerReportsInvalidCodec) {
  DiffCodec<Opaque> codec = OpaqueCodec();
  codec.deserializer = nullptr;
  RecordOrDiffOptions<Opaque> options;
  options.label = "bad_deser";
  const DiffRun rec =
      RecordOutcome([&] { RecordOrDiff(Opaque(1), codec, options); });
  EXPECT_THAT(rec.crash_type,
              Optional(std::string("RecordOrDiff usage error: invalid codec")));
  EXPECT_THAT(rec.stderr_output,
              HasSubstr("for label \"bad_deser\" must have both a serializer "
                        "and a deserializer"));
}

TEST_F(RecordOrDiffTest, CodecDeserializerNulloptReportsUndecodableValue) {
  RecordOrDiffOptions<Opaque> options;
  options.label = "o";
  const std::string container =
      EncodeDiffRecordContainer({{"o", "corrupted_payload"}});
  const DiffRun val = ValidateOutcome(
      container, [&] { RecordOrDiff(Opaque(5), OpaqueCodec(), options); });
  EXPECT_THAT(val.crash_type, Optional(std::string("RecordOrDiff mismatch")));
  EXPECT_THAT(val.stderr_output,
              HasSubstr("Reason: cannot decode baseline value\n"
                        "Expected (baseline): <undecodable: 17 bytes>\n"
                        "Actual (current): \"v=5\"\n"));
}

TEST_F(RecordOrDiffTest, StringViewAndBorrowingTupleValidateMatchingValues) {
  const std::string baseline_str(64, 'a');
  const std::string container = Record([&] {
    RecordOrDiff(std::string_view(baseline_str), "sv");
    RecordOrDiff(absl::string_view(baseline_str), "asv");
    RecordOrDiff(std::make_tuple(std::string_view(baseline_str), 7), "tup");
  });
  const DiffRun val = ValidateOutcome(container, [&] {
    RecordOrDiff(std::string_view(baseline_str), "sv");
    RecordOrDiff(absl::string_view(baseline_str), "asv");
    RecordOrDiff(std::make_tuple(std::string_view(baseline_str), 7), "tup");
  });
  EXPECT_EQ(val.stderr_output, "");
  EXPECT_EQ(val.crash_type, std::nullopt);
}

TEST_F(RecordOrDiffTest, StringViewAndBorrowingTupleReportMismatchesCleanly) {
  const std::string baseline_str(64, 'a');
  const std::string changed_str(64, 'b');
  const std::string container = Record([&] {
    RecordOrDiff(std::string_view(baseline_str), "sv");
    RecordOrDiff(absl::string_view(baseline_str), "asv");
    RecordOrDiff(std::make_tuple(std::string_view(baseline_str), 7), "tup");
  });
  const DiffRun val = ValidateOutcome(container, [&] {
    RecordOrDiff(std::string_view(changed_str), "sv");
    RecordOrDiff(absl::string_view(baseline_str), "asv");
    RecordOrDiff(std::make_tuple(std::string_view(changed_str), 7), "tup");
  });
  EXPECT_THAT(val.crash_type, Optional(std::string("RecordOrDiff mismatch")));
  EXPECT_THAT(val.stderr_output, HasSubstr("Mismatched outputs: 2"));
  EXPECT_THAT(val.stderr_output, HasSubstr("--- RecordOrDiff label: sv"));
  EXPECT_THAT(val.stderr_output, HasSubstr("--- RecordOrDiff label: tup"));
}

TEST_F(RecordOrDiffTest, StringViewLabelsWork) {
  const std::string container = Record([] {
    RecordOrDiff(11, std::string_view("std_sv"));
    RecordOrDiff(22, absl::string_view("absl_sv"));
  });
  const DiffRun val = ValidateOutcome(container, [] {
    RecordOrDiff(11, std::string_view("std_sv"));
    RecordOrDiff(22, absl::string_view("absl_sv"));
  });
  EXPECT_EQ(val.crash_type, std::nullopt);
  EXPECT_EQ(val.stderr_output, "");
}

TEST_F(RecordOrDiffTest, EmptyStringAndEmbeddedNulPayloadsRoundTrip) {
  const std::string nul_str("\0\1\0x", 4);
  const std::string container = Record([&] {
    RecordOrDiff(std::string(""), "empty");
    RecordOrDiff(nul_str, "nul");
  });
  const DiffRun ok = ValidateOutcome(container, [&] {
    RecordOrDiff(std::string(""), "empty");
    RecordOrDiff(nul_str, "nul");
  });
  EXPECT_EQ(ok.crash_type, std::nullopt);

  const DiffRun diff = ValidateOutcome(container, [&] {
    RecordOrDiff(std::string(""), "empty");
    RecordOrDiff(std::string("\0\2\0x", 4), "nul");
  });
  EXPECT_THAT(diff.crash_type, Optional(std::string("RecordOrDiff mismatch")));
}

TEST_F(RecordOrDiffTest, BeginDiffInputResetsPerInputFailureState) {
  const std::string container = Record([] { RecordOrDiff(1, "a"); });
  runtime().EnableDiffMode(DiffMode::kValidate);
  runtime().BeginDiffInput(container, /*unparsable=*/false);
  ::testing::internal::CaptureStderr();
  RecordOrDiff(2, "a");
  runtime().CheckDiffRecordsAtInputEnd();
  (void)::testing::internal::GetCapturedStderr();
  ASSERT_TRUE(runtime().crash_type().has_value());
  EXPECT_TRUE(runtime().ShouldSkipDiffCall());
  runtime().SetExternalFailureDetected(true);

  // The next input starts clean and is not reported.
  runtime().BeginDiffInput(container, /*unparsable=*/false);
  EXPECT_EQ(runtime().crash_type(), std::nullopt);
  EXPECT_FALSE(runtime().external_failure_detected());
  EXPECT_FALSE(runtime().ShouldSkipDiffCall());
  RecordOrDiff(1, "a");
  runtime().CheckDiffRecordsAtInputEnd();
  EXPECT_EQ(runtime().crash_type(), std::nullopt);
}

}  // namespace
}  // namespace fuzztest
