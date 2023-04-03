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

#include "./centipede/blob_file.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/span.h"
#include "./centipede/test_util.h"
#include "./centipede/util.h"

namespace centipede {
namespace {

std::string TempFilePath() {
  return GetTestTempDir().append("blob_file");
}

// Tests correct way of using a BlobFile.
// We may have more than one BlobFile factory.
// Need to test every factory the same way.
void TestOneBlobFile(std::unique_ptr<BlobFileReader> (*ReaderFactory)(),
                     std::unique_ptr<BlobFileAppender> (*AppenderFactory)()) {
  ByteArray input1{1, 2, 3};
  ByteArray input2{4, 5};
  ByteArray input3{6, 7, 8, 9};
  const auto path = TempFilePath();
  absl::Span<uint8_t> blob;

  // Append two blobs to a file.
  {
    auto appender = AppenderFactory();
    EXPECT_OK(appender->Open(path));
    EXPECT_OK(appender->Append(input1));
    EXPECT_OK(appender->Append(input2));
    EXPECT_OK(appender->Close());
  }

  // Read the blobs back.
  {
    auto reader = ReaderFactory();
    EXPECT_OK(reader->Open(path));
    EXPECT_OK(reader->Read(blob));
    EXPECT_EQ(input1, blob);
    EXPECT_OK(reader->Read(blob));
    EXPECT_EQ(input2, blob);
    EXPECT_EQ(reader->Read(blob), absl::OutOfRangeError("no more blobs"));
    EXPECT_OK(reader->Close());
  }

  // Append one more blob to the same file.
  {
    auto appender = AppenderFactory();
    EXPECT_OK(appender->Open(path));
    EXPECT_OK(appender->Append(input3));
    EXPECT_OK(appender->Close());
  }

  // Re-read the file, expect to see all 3 blobs.
  {
    auto reader = ReaderFactory();
    EXPECT_OK(reader->Open(path));
    EXPECT_OK(reader->Read(blob));
    EXPECT_EQ(input1, blob);
    EXPECT_OK(reader->Read(blob));
    EXPECT_EQ(input2, blob);
    EXPECT_OK(reader->Read(blob));
    EXPECT_EQ(input3, blob);
    EXPECT_EQ(reader->Read(blob), absl::OutOfRangeError("no more blobs"));
    EXPECT_OK(reader->Close());
  }
}

TEST(BlobFile, DefaultTest) {
  TestOneBlobFile(&DefaultBlobFileReaderFactory,
                  &DefaultBlobFileAppenderFactory);
}

// Tests incorrect ways of using a BlobFileReader/BlobFileAppender.
void TestIncorrectUsage(
    std::unique_ptr<BlobFileReader> (*ReaderFactory)(),
    std::unique_ptr<BlobFileAppender> (*AppenderFactory)()) {
  const std::string invalid_path = "/DOES/NOT/EXIST";
  const auto path = TempFilePath();
  auto reader = ReaderFactory();
  auto appender = AppenderFactory();

  // open invalid file path.
  EXPECT_EQ(reader->Open(invalid_path), absl::UnknownError("can't open file"));
  EXPECT_EQ(appender->Open(invalid_path),
            absl::UnknownError("can't open file"));
  absl::Span<uint8_t> blob;

  // Use the calls in the wrong order, e.g. Close() before Open(), etc.

  // Appender first, it will create `path` if it doesn't exist.
  EXPECT_EQ(appender->Close(), absl::FailedPreconditionError("was not open"));
  EXPECT_EQ(appender->Append(blob),
            absl::FailedPreconditionError("was not open"));
  EXPECT_OK(appender->Open(path));
  EXPECT_EQ(appender->Open(path),
            absl::FailedPreconditionError("already open"));
  EXPECT_OK(appender->Close());
  EXPECT_EQ(appender->Append(blob),
            absl::FailedPreconditionError("already closed"));
  EXPECT_EQ(appender->Open(path),
            absl::FailedPreconditionError("already closed"));
  EXPECT_EQ(appender->Close(), absl::FailedPreconditionError("already closed"));

  // Now the reader.
  EXPECT_EQ(reader->Close(), absl::FailedPreconditionError("was not open"));
  EXPECT_EQ(reader->Read(blob), absl::FailedPreconditionError("was not open"));
  EXPECT_OK(reader->Open(path));
  EXPECT_EQ(reader->Open(path), absl::FailedPreconditionError("already open"));
  EXPECT_OK(reader->Close());
  EXPECT_EQ(reader->Read(blob),
            absl::FailedPreconditionError("already closed"));
  EXPECT_EQ(reader->Open(path),
            absl::FailedPreconditionError("already closed"));
  EXPECT_EQ(reader->Close(), absl::FailedPreconditionError("already closed"));
}

TEST(BlobFile, IncorrectUsage) {
  TestIncorrectUsage(&DefaultBlobFileReaderFactory,
                     &DefaultBlobFileAppenderFactory);
}

}  // namespace
}  // namespace centipede
