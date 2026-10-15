// Copyright 2025 Google LLC
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

#include "./fuzztest/internal/sanitizer_interface.h"

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/attributes.h"
#include "absl/base/optimization.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"

namespace fuzztest::internal {

std::vector<std::string> CollectTopAppFunctions(int max_frames) {
  if (max_frames <= 0) {
    char symbol_storage[1024];
    const absl::Span<const absl::string_view> frames =
        GetTopAppFunctions({}, symbol_storage);
    return std::vector<std::string>(frames.begin(), frames.end());
  }
  std::vector<absl::string_view> frame_storage(max_frames);
  char symbol_storage[10 * 1024];
  const absl::Span<const absl::string_view> frames =
      GetTopAppFunctions(absl::MakeSpan(frame_storage), symbol_storage);
  return std::vector<std::string>(frames.begin(), frames.end());
}

}  // namespace fuzztest::internal

namespace test_app {

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> Helper4(int max_frames) {
  auto frames = fuzztest::internal::CollectTopAppFunctions(max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> Helper3(int max_frames) {
  auto frames = Helper4(max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> Helper2(int max_frames) {
  auto frames = Helper3(max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> Helper1(int max_frames) {
  auto frames = Helper2(max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

struct Functor {
  ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> operator()(
      int max_frames) const {
    auto frames = fuzztest::internal::CollectTopAppFunctions(max_frames);
    ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
    return frames;
  }
};

struct Buffer {
  ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> operator[](
      int max_frames) const {
    Functor functor;
    auto frames = functor(max_frames);
    ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
    return frames;
  }
};

}  // namespace test_app

namespace {

#if defined(__GNUC__) || defined(__clang__)
__attribute__((__abi_tag__("cxx11")))
#endif
ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> AnonAppHelper(int max_frames) {
  test_app::Buffer buffer;
  auto frames = buffer[max_frames];
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

}  // namespace

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> FuzzTestUserFunction(
    int max_frames) {
  auto frames = AnonAppHelper(max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

// Functions and namespaces matching internal frame prefixes in
// `IsInternalFrame` to verify they are skipped during stack unwinding.
ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> __fake_double_underscore_frame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = next(max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> sanitizer_fake_frame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = __fake_double_underscore_frame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> asan_fake_frame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = sanitizer_fake_frame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> msan_fake_frame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = asan_fake_frame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> tsan_fake_frame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = msan_fake_frame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> ubsan_fake_frame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = tsan_fake_frame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> lsan_fake_frame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = ubsan_fake_frame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> hwasan_fake_frame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = lsan_fake_frame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> SignalAction(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = hwasan_fake_frame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> SignalHandler(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = SignalAction(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> FuzzTestWorkerFakeFrame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = SignalHandler(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> CentipedeFakeFrame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = FuzzTestWorkerFakeFrame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> LLVMFuzzerFakeFrame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = CentipedeFakeFrame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

namespace centipede {
ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> FakeCentipedeNamespaceFrame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = LLVMFuzzerFakeFrame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}
}  // namespace centipede

namespace tcmalloc {
ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> FakeTcmallocFrame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = centipede::FakeCentipedeNamespaceFrame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}
}  // namespace tcmalloc

namespace absl {
ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> FakeAbslFrame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = tcmalloc::FakeTcmallocFrame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}
}  // namespace absl

namespace testing {
namespace internal {
ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> FakeGTestInternalFrame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = absl::FakeAbslFrame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}
}  // namespace internal

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> FakeGTestFrame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = internal::FakeGTestInternalFrame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}
}  // namespace testing

namespace fuzztest {
ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> FakeFuzzTestFrame(
    const std::function<std::vector<std::string>(int)>& next, int max_frames) {
  auto frames = testing::FakeGTestFrame(next, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}
}  // namespace fuzztest

namespace test_app {

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> InnerAppFunc(int max_frames) {
  auto frames = fuzztest::FakeFuzzTestFrame(
      &fuzztest::internal::CollectTopAppFunctions, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

ABSL_ATTRIBUTE_NOINLINE std::vector<std::string> OuterAppFunc(int max_frames) {
  auto frames = fuzztest::FakeFuzzTestFrame(&InnerAppFunc, max_frames);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
  return frames;
}

}  // namespace test_app

namespace fuzztest::internal {
namespace {

using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::IsEmpty;

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeWhenItIsTheOnlyToken) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: SomeSanitizer: some-crash-type");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "some-crash-type");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeWhenFilePathIsPresent) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: AddressSanitizer: heap-use-after-free some/file.cc:1234:5");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "heap-use-after-free");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, ParsesMemoryLeak) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: AddressSanitizer: 10 byte(s) leaked in 10 allocation(s)");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "memory-leak");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, ExtractsCrashTypeForUBSan) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: UndefinedBehaviorSanitizer: null-pointer-use "
          "some/file.h:32:7");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "null-pointer-use");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, ExtractsCrashTypeForMSan) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: MemorySanitizer: use-of-uninitialized-value "
          "some/file.cc:570:11 in SomeFunction");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "use-of-uninitialized-value");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanDataRaceOnVptr) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: data race on vptr (ctor/dtor vs virtual "
          "call) some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "data-race");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, ExtractsCrashTypeForTSanDataRace) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: data race "
          "some/file.cc:33:37 in operator()");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "data-race");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanDestroyLocked) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: destroy of a locked mutex "
          "some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "destroy-locked-mutex");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanDoubleLock) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: double lock of a mutex some/file.cc:12:34 "
          "in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "double-lock-of-mutex");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, ExtractsCrashTypeForTSanDeadlock) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: lock-order-inversion (potential "
          "deadlock) some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "lock-order-inversion");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanMutexHeldWrongContext) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: mutex held in the wrong context "
          "some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "mutex-held-in-wrong-context");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanExternalRace) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: race on external object "
          "some/file.cc:12:34 "
          "in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "data-race");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanBadReadLock) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: read lock of a write locked mutex "
          "some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "read-lock-of-write-locked-mutex");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanBadReadUnlock) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: read unlock of a write locked mutex "
          "some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "read-unlock-of-write-locked-mutex");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanErrnoInSignal) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: signal handler spoils errno "
          "some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "signal-handler-spoils-errno");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanSignalUnsafe) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: signal-unsafe call inside of a signal "
          "some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "signal-unsafe-call-inside-of-a-signal");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanSwiftAccessRace) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: Swift access race some/file.cc:12:34 in "
          "Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "data-race");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanThreadLeak) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: thread leak some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "thread-leak");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanBadUnlock) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: unlock of an unlocked mutex (or by a "
          "wrong thread) some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "unlock-unlocked-mutex");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanInvalidMutex) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: use of an invalid mutex (e.g. "
          "uninitialized or destroyed) some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "use-invalid-mutex");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanHeapUseAfterFree) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: heap-use-after-free some/file.cc:12:34 "
          "in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "heap-use-after-free");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanFallbackSingleToken) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: unknown-crash-type some/file.cc:12:34 "
          "in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "unknown-crash-type");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, IgnoresTsanCrashTypeForNonTSan) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: AddressSanitizer: data race some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "data");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, FailsOnMissingSummaryPrefix) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary("Missing SUMMARY prefix");
  ASSERT_FALSE(crash_type.ok());
  EXPECT_THAT(crash_type.status().message(),
              HasSubstr("Missing SUMMARY prefix"));
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, FailsOnMissingSanitizerName) {
  const absl::StatusOr<absl::string_view> crash_type =
      ParseCrashTypeFromSanitizerSummary("SUMMARY: No sanitizer name");
  ASSERT_FALSE(crash_type.ok());
  EXPECT_THAT(crash_type.status().message(), HasSubstr("No sanitizer name"));
}

extern "C" void __sanitizer_report_error_summary(const char* error_summary);

void InvokeSanitizerReportErrorSummary(const char* error_summary) {
  __sanitizer_report_error_summary(error_summary);
}

TEST(FuzzTestSanitizerErrorSummaryCallbackTest,
     InvokesCallbackWithParsedOrFallbackCrashType) {
  static absl::string_view recorded_crash_type;
  recorded_crash_type = "unset";

  FuzzTestSetSanitizerErrorSummaryCallback(nullptr);
  InvokeSanitizerReportErrorSummary(
      "SUMMARY: AddressSanitizer: heap-use-after-free some/file.cc:12:3");
  EXPECT_EQ(recorded_crash_type, "unset");

  FuzzTestSetSanitizerErrorSummaryCallback([](const char* crash_type_data,
                                              size_t crash_type_size) {
    recorded_crash_type = absl::string_view(crash_type_data, crash_type_size);
  });

  InvokeSanitizerReportErrorSummary(
      "SUMMARY: AddressSanitizer: heap-use-after-free some/file.cc:12:3");
  EXPECT_EQ(recorded_crash_type, "heap-use-after-free");

  InvokeSanitizerReportErrorSummary(nullptr);
  EXPECT_EQ(recorded_crash_type, "Sanitizer crash");

  InvokeSanitizerReportErrorSummary("Invalid summary");
  EXPECT_EQ(recorded_crash_type, "Sanitizer crash");

  FuzzTestSetSanitizerErrorSummaryCallback(nullptr);
}

TEST(GetTopAppFunctionsTest, CapturesTopApplicationFunctionsFromCallStack) {
  EXPECT_THAT(test_app::Helper1(3),
              ElementsAre("test_app::Helper4", "test_app::Helper3",
                          "test_app::Helper2"));
  EXPECT_THAT(test_app::Helper1(2),
              ElementsAre("test_app::Helper4", "test_app::Helper3"));
  // Requesting more frames than exist in `test_app` walks the rest of the
  // stack (`fuzztest::internal`, `testing::internal`, `testing::Test::Run`,
  // `main`, `__libc_start_main`, `_start`) and filters all of them out.
  EXPECT_THAT(test_app::Helper1(10),
              ElementsAre("test_app::Helper4", "test_app::Helper3",
                          "test_app::Helper2", "test_app::Helper1"));
  EXPECT_THAT(test_app::Helper1(0), IsEmpty());
  EXPECT_THAT(test_app::Helper1(-1), IsEmpty());
}

TEST(GetTopAppFunctionsTest,
     FiltersOutSanitizerFuzzTestGTestAbseilAndStlFrames) {
  EXPECT_THAT(test_app::OuterAppFunc(10),
              ElementsAre("test_app::InnerAppFunc", "test_app::OuterAppFunc"));
}

TEST(GetTopAppFunctionsTest,
     PreservesUserOperatorsAnonNamespacesAndFuzzTestPrefixedUserNames) {
  EXPECT_THAT(FuzzTestUserFunction(10),
              ElementsAre("test_app::Functor::operator()",
                          "test_app::Buffer::operator[]",
                          "(anonymous namespace)::AnonAppHelper",
                          "FuzzTestUserFunction"));
}

TEST(FormatStackCrashSignatureTest, FormatsCrashTypeAndFrames) {
  char out_buffer[256];
  EXPECT_EQ(FormatStackCrashSignature("heap-buffer-overflow", {}, out_buffer),
            "heap-buffer-overflow");
  EXPECT_EQ(FormatStackCrashSignature("heap-buffer-overflow",
                                      {"MyApp::ParseHeader"}, out_buffer),
            "heap-buffer-overflow:MyApp::ParseHeader");
  EXPECT_EQ(FormatStackCrashSignature(
                "heap-buffer-overflow",
                {"Buffer::operator[]", "MyApp::ParseHeader", "ProcessPacket"},
                out_buffer),
            "heap-buffer-overflow:Buffer::operator[]/MyApp::ParseHeader/"
            "ProcessPacket");
}

}  // namespace
}  // namespace fuzztest::internal
