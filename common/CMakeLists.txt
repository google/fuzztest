# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if (NOT COMPILER_GCC)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize-coverage=0")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize-coverage=0")
endif()

### Libraries

fuzztest_cc_library(
  NAME
    bazel
  HDRS
    "bazel.h"
  SRCS
    "bazel.cc"
  DEPS
    absl::check
    absl::strings
    absl::status
    absl::time
)

fuzztest_cc_library(
  NAME
    blob_file
  HDRS
    "blob_file.h"
  SRCS
    "blob_file.cc"
  DEFINES
    # Riegeli doesn't yet support CMake builds:
    # https://github.com/google/riegeli/issues/16
    CENTIPEDE_DISABLE_RIEGELI
  DEPS
    fuzztest::common_logging
    fuzztest::defs
    fuzztest::hash
    fuzztest::remote_file
    fuzztest::status_macros
    absl::check
    absl::core_headers
    absl::log
    absl::nullability
    absl::status
    absl::statusor
    absl::str_format
    absl::string_view
    absl::time
)

fuzztest_cc_library(
  NAME
    defs
  HDRS
    "defs.h"
  DEPS
    absl::span
)

fuzztest_cc_library(
  NAME
    hash
  HDRS
    "hash.h"
  SRCS
    "hash.cc"
  DEPS
    fuzztest::defs
    fuzztest::sha1
)

fuzztest_cc_library(
  NAME
    common_logging
  HDRS
    "logging.h"
  DEPS
    absl::check
    absl::log
)

fuzztest_cc_library(
  NAME
    remote_file
  HDRS
    "remote_file.h"
  SRCS
    "remote_file.cc"
    "remote_file_oss.cc"
  DEFINES
    # Riegeli doesn't yet support CMake builds:
    # https://github.com/google/riegeli/issues/16
    CENTIPEDE_DISABLE_RIEGELI
  DEPS
    fuzztest::common_logging
    fuzztest::defs
    fuzztest::status_macros
    absl::check
    absl::log
    absl::nullability
    absl::status
    absl::statusor
    absl::strings
)

fuzztest_cc_library(
  NAME
    sha1
  HDRS
    "sha1.h"
  SRCS
    "sha1.cc"
  DEPS
    absl::nullability
)

fuzztest_cc_library(
  NAME
    status_macros
  HDRS
    "status_macros.h"
  DEPS
    absl::core_headers
    absl::log
)

fuzztest_cc_library(
  NAME
    test_util
  HDRS
    "test_util.h"
  SRCS
    "test_util.cc"
  DEPS
    fuzztest::common_logging
    fuzztest::blob_file
    fuzztest::defs
    absl::check
    absl::log
    absl::strings
    absl::str_format
    GTest::gtest
  TESTONLY
)

fuzztest_cc_library(
  NAME
    temp_dir
  HDRS
    "temp_dir.h"
  SRCS
    "temp_dir.cc"
  DEPS
    absl::check
    absl::string_view
    absl::strings
)

### Tests

fuzztest_cc_test(
  NAME
    blob_file_test
  SRCS
    "blob_file_test.cc"
  DEPS
    fuzztest::blob_file
    fuzztest::defs
    fuzztest::test_util
    absl::status
    GTest::gmock_main
)

fuzztest_cc_test(
  NAME
    hash_test
  SRCS
    "hash_test.cc"
  DEPS
    fuzztest::hash
    GTest::gmock_main
)

fuzztest_cc_test(
  NAME
    remote_file_test
  SRCS
    "remote_file_test.cc"
  DEPS
    fuzztest::common_logging
    fuzztest::remote_file
    fuzztest::test_util
    absl::check
    absl::status
    absl::time
    GTest::gmock_main
)
