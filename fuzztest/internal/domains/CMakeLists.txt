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
    absl_helpers
  HDRS
    "absl_helpers.h"
  DEPS
    absl::time
    fuzztest::logging
)

fuzztest_cc_library(
  NAME
    core_domains_impl
  HDRS
    "aggregate_of_impl.h"
    "arbitrary_impl.h"
    "bit_flag_combination_of_impl.h"
    "bit_gen_ref.h"
    "container_mutation_helpers.h"
    "container_of_impl.h"
    "domain.h"
    "domain_base.h"
    "domain_type_erasure.h"
    "element_of_impl.h"
    "filter_impl.h"
    "flat_map_impl.h"
    "in_range_impl.h"
    "map_impl.h"
    "mutation_metadata.h"
    "one_of_impl.h"
    "optional_of_impl.h"
    "overlap_of_impl.h"
    "serialization_helpers.h"
    "smart_pointer_of_impl.h"
    "special_values.h"
    "unique_elements_container_of_impl.h"
    "value_mutation_helpers.h"
    "variant_of_impl.h"
  DEPS
    fuzztest::absl_helpers
    absl::flat_hash_set
    absl::function_ref
    absl::absl_check
    absl::absl_log
    absl::bits
    absl::int128
    absl::random_random
    absl::random_bit_gen_ref
    absl::random_distributions
    absl::status
    absl::strings
    absl::str_format
    absl::time
    absl::span
    fuzztest::fuzzing_bit_gen
    fuzztest::any
    fuzztest::logging
    fuzztest::meta
    fuzztest::printer
    fuzztest::serialization
    fuzztest::status
    fuzztest::table_of_recent_compares
    fuzztest::type_support
)

fuzztest_cc_library(
  NAME
    domains_impl
  HDRS
    "domain_base.h"
    "domain_type_erasure.h"
  DEPS
    fuzztest::core_domains_impl
    fuzztest::in_grammar_impl
    fuzztest::in_regexp_impl
    fuzztest::protobuf_domain_impl
    absl::core_headers
    absl::no_destructor
    absl::flat_hash_map
    absl::flat_hash_set
    absl::function_ref
    absl::random_random
    absl::random_bit_gen_ref
    absl::random_distributions
    absl::status
    absl::statusor
    absl::strings
    absl::str_format
    absl::synchronization
    absl::span
    fuzztest::domain_core
    fuzztest::any
    fuzztest::logging
    fuzztest::meta
    fuzztest::printer
    fuzztest::serialization
    fuzztest::status
    fuzztest::type_support
)

fuzztest_cc_library(
  NAME
    in_grammar_impl
  HDRS
    "in_grammar_impl.h"
  SRCS
    "in_grammar_impl.cc"
  DEPS
    fuzztest::core_domains_impl
    fuzztest::in_regexp_impl
    fuzztest::regexp_dfa
    absl::flat_hash_map
    absl::random_bit_gen_ref
    absl::random_distributions
    absl::status
    absl::strings
    absl::string_view
    absl::span
    fuzztest::logging
    fuzztest::meta
    fuzztest::serialization
    fuzztest::type_support
)

fuzztest_cc_library(
  NAME
    in_regexp_impl
  HDRS
    "in_regexp_impl.h"
  SRCS
    "in_regexp_impl.cc"
  DEPS
    fuzztest::core_domains_impl
    fuzztest::regexp_dfa
    absl::random_bit_gen_ref
    absl::random_distributions
    absl::status
    absl::statusor
    absl::strings
    absl::span
    fuzztest::logging
    fuzztest::serialization
    fuzztest::status
    fuzztest::type_support
)

fuzztest_cc_library(
  NAME
    protobuf_domain_impl
  HDRS
    "protobuf_domain_impl.h"
  DEPS
    fuzztest::core_domains_impl
    absl::core_headers
    absl::no_destructor
    absl::flat_hash_map
    absl::flat_hash_set
    absl::random_random
    absl::random_bit_gen_ref
    absl::status
    absl::str_format
    absl::string_view
    absl::synchronization
    absl::span
    fuzztest::domain_core
    fuzztest::any
    fuzztest::logging
    fuzztest::meta
    fuzztest::serialization
    fuzztest::status
    fuzztest::type_support
)

fuzztest_cc_library(
  NAME
    regexp_dfa
  HDRS
    "regexp_dfa.h"
  SRCS
    "regexp_dfa.cc"
  DEPS
    absl::flat_hash_map
    absl::random_bit_gen_ref
    absl::random_distributions
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    fuzztest::logging
    re2::re2
)

fuzztest_cc_library(
  NAME
    utf
  HDRS
    "utf.h"
  SRCS
    "rune.cc"
    "rune.h"
    "utf.cc"
  DEPS
    absl::string_view
)
