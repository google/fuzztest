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

fuzztest_cc_library(
  NAME
    domain
  HDRS
    "domain.h"
  DEPS
    fuzztest::domain_core
    fuzztest::domains_impl
    fuzztest::in_regexp_impl
    fuzztest::protobuf_domain_impl
)

fuzztest_cc_library(
  NAME
    domain_core
  HDRS
    "domain_core.h"
  DEPS
    absl::flat_hash_map
    absl::random_bit_gen_ref
    absl::status
    absl::string_view
    absl::span
    fuzztest::any
    fuzztest::logging
    fuzztest::meta
    fuzztest::printer
    fuzztest::serialization
    fuzztest::type_support
    fuzztest::core_domains_impl
    fuzztest::utf
)

fuzztest_cc_library(
  NAME
    fuzzing_bit_gen
  HDRS
    "fuzzing_bit_gen.h"
  SRCS
    "fuzzing_bit_gen.cc"
  DEPS
    absl::fast_type_id
    absl::no_destructor
    absl::flat_hash_map
    absl::bits
    absl::int128
    absl::random_bit_gen_ref
    absl::span
    fuzztest::register_fuzzing_mocks
)

fuzztest_cc_library(
  NAME
    fuzztest
  HDRS
    "fuzztest.h"
  DEPS
    fuzztest::domain
    fuzztest::fuzztest_macros
)

fuzztest_cc_library(
  NAME
    fuzztest_core
  HDRS
    "fuzztest_core.h"
  DEPS
    fuzztest::domain_core
    fuzztest::fuzztest_macros
)

fuzztest_cc_library(
  NAME
    fuzztest_gtest_main
  SRCS
    "fuzztest_gtest_main.cc"
  DEPS
    fuzztest::init_fuzztest
    GTest::gtest
)

fuzztest_cc_library(
  NAME
    fuzztest_macros
  HDRS
    "fuzztest_macros.h"
  SRCS
    "fuzztest_macros.cc"
  DEPS
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    fuzztest::logging
    fuzztest::registration
    fuzztest::registry
    fuzztest::runtime
)

fuzztest_cc_test(
  NAME
    fuzztest_macros_test
  SRCS
    "fuzztest_macros_test.cc"
  DEPS
    fuzztest::fuzztest_macros
    absl::check
    absl::status
    absl::strings
    fuzztest::temp_dir
    GTest::gmock_main
)

fuzztest_cc_library(
  NAME
    googletest_fixture_adapter
  HDRS
    "googletest_fixture_adapter.h"
  DEPS
    fuzztest::fixture_driver
    GTest::gtest
)

fuzztest_cc_library(
  NAME
    init_fuzztest
  HDRS
    "init_fuzztest.h"
  SRCS
    "init_fuzztest.cc"
  DEPS
    absl::algorithm_container
    absl::no_destructor
    absl::flat_hash_set
    absl::flags
    absl::flags_parse
    absl::flags_reflection
    absl::strings
    absl::str_format
    absl::time
    fuzztest::configuration
    fuzztest::flag_name
    fuzztest::googletest_adaptor
    fuzztest::io
    fuzztest::logging
    fuzztest::registry
    fuzztest::runtime
    GTest::gtest
)

fuzztest_cc_library(
  NAME
    llvm_fuzzer_main
  SRCS
    "llvm_fuzzer_main.cc"
  DEPS
    fuzztest::init_fuzztest
    absl::flags
    absl::flags_parse
    GTest::gtest
)

fuzztest_cc_library(
  NAME
    llvm_fuzzer_wrapper
  SRCS
    "llvm_fuzzer_wrapper.cc"
  DEPS
    fuzztest::fuzztest
    fuzztest::fuzztest_macros
    absl::core_headers
    absl::no_destructor
    absl::flags
    absl::absl_check
    absl::random_random
    absl::random_bit_gen_ref
    absl::synchronization
    fuzztest::io
    fuzztest::logging
    fuzztest::core_domains_impl
)
