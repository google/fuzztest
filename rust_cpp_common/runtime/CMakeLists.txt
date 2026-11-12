# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
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
    sanitizer_interface
  HDRS
    "sanitizer_interface.h"
  SRCS
    "sanitizer_interface.cc"
  DEPS
    fuzztest::common_logging
    fuzztest::symbol_name_utils
    absl::config
    absl::core_headers
    absl::stacktrace
    absl::status
    absl::statusor
    absl::strings
    absl::symbolize
    absl::span
)

fuzztest_cc_library(
  NAME
    symbol_name_utils
  HDRS
    "symbol_name_utils.h"
  DEPS
    absl::string_view
)

### Tests

fuzztest_cc_test(
  NAME
    sanitizer_interface_test
  SRCS
    "sanitizer_interface_test.cc"
  DEPS
    fuzztest::sanitizer_interface
    absl::config
    absl::core_headers
    absl::span
    absl::status
    absl::statusor
    absl::str_format
    absl::string_view
    GTest::gmock_main
)
