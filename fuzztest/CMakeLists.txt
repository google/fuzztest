function(_link_libfuzzer_in_compatibility_mode name)
  if (FUZZTEST_COMPATIBILITY_MODE STREQUAL "libfuzzer")
    EXECUTE_PROCESS (
        COMMAND bash -c "find \${PATH//:/ } -maxdepth 1 -executable -name 'llvm-config*'"
        OUTPUT_VARIABLE LLVM_CONFIG OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    EXECUTE_PROCESS(
      COMMAND bash -c "find $(${LLVM_CONFIG} --libdir) \
      -name libclang_rt.fuzzer_no_main-x86_64.a"
      OUTPUT_VARIABLE FUZZER_NO_MAIN OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT FUZZER_NO_MAIN)
      # LLVM_ENABLE_PER_TARGET_RUNTIME_DIR was set to ON when building LLVM.
      EXECUTE_PROCESS(
        COMMAND bash -c "find / -regex \
        \"$(${LLVM_CONFIG} --libdir).*$(${LLVM_CONFIG} --host-target).*libclang_rt.fuzzer_no_main.a\""
        OUTPUT_VARIABLE FUZZER_NO_MAIN OUTPUT_STRIP_TRAILING_WHITESPACE
      )
    endif()
    target_link_libraries(${name} PRIVATE ${FUZZER_NO_MAIN})
  endif ()
endfunction()

get_filename_component(PARENT_DIR ../ ABSOLUTE)
include_directories(${PARENT_DIR})

add_subdirectory(grammars)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize-coverage=0")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize-coverage=0")

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
    fuzztest_macros
  HDRS
    "fuzztest_macros.h"
  SRCS
    "fuzztest_macros.cc"
  DEPS
    fuzztest::io
    fuzztest::registration
    fuzztest::registry
)

fuzztest_cc_library(
  NAME
    fuzztest_gtest_main
  SRCS
    "fuzztest_gtest_main.cc"
  DEPS
    absl::flags_parse
    absl::strings
    fuzztest::init_fuzztest
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
    fuzztest::configuration
    fuzztest::googletest_adaptor
    fuzztest::io
    fuzztest::logging
    fuzztest::registry
    fuzztest::runtime
    absl::algorithm_container
    absl::flags
    absl::flags_parse
    absl::flags_reflection
    absl::flat_hash_set
    absl::no_destructor
    absl::strings
    absl::str_format
    absl::time
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
    fuzztest::domain_core
    fuzztest::fuzztest
    fuzztest::io
    fuzztest::llvm_fuzzer_main
    absl::flags
    absl::log
    absl::random_random
    absl::random_bit_gen_ref
    absl::strings
    absl::string_view
    re2::re2
)

################################################################################
# Internal
################################################################################

# TODO(lszekeres): Move these under internal/CMakeLists.txt

fuzztest_cc_library(
  NAME
    absl_helpers
  HDRS
    "internal/domains/absl_helpers.h"
  DEPS
    fuzztest::logging
    absl::time
)

fuzztest_cc_library(
  NAME
    any
  HDRS
    "internal/any.h"
  DEPS
    fuzztest::logging
    fuzztest::meta
)

fuzztest_cc_test(
  NAME
    any_test
  SRCS
    "internal/any_test.cc"
  DEPS
    fuzztest::any
    absl::strings
    GTest::gmock_main
)

# TODO(lszekeres): centipede_adaptor

fuzztest_cc_library(
  NAME
    compatibility_mode
  HDRS
    "internal/compatibility_mode.h"
  SRCS
    "internal/compatibility_mode.cc"
  DEPS
    fuzztest::domain_core
    fuzztest::fixture_driver
    fuzztest::logging
    fuzztest::runtime
    absl::random_distributions
    absl::strings
    absl::str_format
    absl::time
)

_link_libfuzzer_in_compatibility_mode(fuzztest_compatibility_mode)

fuzztest_cc_library(
  NAME
    configuration
  HDRS
    "internal/configuration.h"
  SRCS
    "internal/configuration.cc"
  DEPS
    absl::check
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    absl::time
)

fuzztest_cc_test(
  NAME
    configuration_test
  SRCS
    "internal/configuration_test.cc"
  DEPS
    fuzztest::configuration
    absl::statusor
    absl::time
    GTest::gmock_main
)

fuzztest_cc_library(
  NAME
    corpus_database
  HDRS
    "internal/corpus_database.h"
  SRCS
    "internal/corpus_database.cc"
  DEPS
    fuzztest::configuration
    fuzztest::io
    absl::strings
    absl::string_view
)

fuzztest_cc_library(
  NAME
    coverage
  HDRS
    "internal/coverage.h"
  SRCS
    "internal/coverage.cc"
  DEPS
    fuzztest::logging
    fuzztest::table_of_recent_compares
    absl::core_headers
    absl::str_format
    absl::span
)

fuzztest_cc_library(
  NAME
    domain
  HDRS
    "domain.h"
    "internal/domains/in_grammar_impl.h"
    "internal/domains/in_regexp_impl.h"
    "internal/domains/protobuf_domain_impl.h"
  SRCS
    "internal/domains/in_grammar_impl.cc"
  DEPS
    fuzztest::any
    fuzztest::domain_core
    fuzztest::logging
    fuzztest::meta
    fuzztest::regexp_dfa
    fuzztest::serialization
    fuzztest::status
    fuzztest::type_support
    absl::core_headers
    absl::flat_hash_map
    absl::flat_hash_set
    absl::random_random
    absl::random_bit_gen_ref
    absl::random_distributions
    absl::status
    absl::statusor
    absl::strings
    absl::synchronization
    absl::span
)

fuzztest_cc_library(
  NAME
    domain_core
  HDRS
    "domain_core.h"
    "internal/domains/aggregate_of_impl.h"
    "internal/domains/arbitrary_impl.h"
    "internal/domains/bit_flag_combination_of_impl.h"
    "internal/domains/container_mutation_helpers.h"
    "internal/domains/container_of_impl.h"
    "internal/domains/domain.h"
    "internal/domains/domain_base.h"
    "internal/domains/domain_type_erasure.h"
    "internal/domains/element_of_impl.h"
    "internal/domains/filter_impl.h"
    "internal/domains/flat_map_impl.h"
    "internal/domains/in_range_impl.h"
    "internal/domains/map_impl.h"
    "internal/domains/one_of_impl.h"
    "internal/domains/optional_of_impl.h"
    "internal/domains/overlap_of_impl.h"
    "internal/domains/serialization_helpers.h"
    "internal/domains/smart_pointer_of_impl.h"
    "internal/domains/special_values.h"
    "internal/domains/unique_elements_container_of_impl.h"
    "internal/domains/value_mutation_helpers.h"
    "internal/domains/variant_of_impl.h"
  SRCS
    "internal/domains/domain_base.cc"
  DEPS
    fuzztest::absl_helpers
    fuzztest::any
    fuzztest::coverage
    fuzztest::logging
    fuzztest::meta
    fuzztest::printer
    fuzztest::seed_seq
    fuzztest::serialization
    fuzztest::status
    fuzztest::table_of_recent_compares
    fuzztest::type_support
    absl::flat_hash_map
    absl::flat_hash_set
    absl::function_ref
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
)

fuzztest_cc_library(
  NAME
    fixture_driver
  HDRS
    "internal/fixture_driver.h"
  SRCS
    "internal/fixture_driver.cc"
  DEPS
    fuzztest::any
    fuzztest::domain_core
    fuzztest::logging
    fuzztest::meta
    fuzztest::printer
    fuzztest::registration
    fuzztest::type_support
    absl::status
    absl::str_format
    absl::span
)

fuzztest_cc_test(
  NAME
    fixture_driver_test
  SRCS
    "internal/fixture_driver_test.cc"
  DEPS
    fuzztest::any
    fuzztest::domain_core
    fuzztest::fixture_driver
    fuzztest::logging
    fuzztest::registration
    absl::span
    GTest::gmock_main
)

fuzztest_cc_library(
  NAME
    googletest_adaptor
  HDRS
    "internal/googletest_adaptor.h"
  SRCS
    "internal/googletest_adaptor.cc"
  DEPS
    fuzztest::configuration
    fuzztest::corpus_database
    fuzztest::io
    fuzztest::registry
    fuzztest::runtime
    absl::strings
    absl::string_view
    absl::str_format
    GTest::gtest
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
    io
  HDRS
    "internal/io.h"
  SRCS
    "internal/io.cc"
  DEPS
    fuzztest::blob_file
    fuzztest::defs
    fuzztest::logging
    fuzztest::remote_file
    absl::function_ref
    absl::hash
    absl::status
    absl::str_format
    absl::string_view
    absl::span
)

fuzztest_cc_test(
  NAME
    io_test
  SRCS
    "internal/io_test.cc"
  DEPS
    fuzztest::blob_file
    fuzztest::defs
    fuzztest::fuzztest_core
    fuzztest::io
    absl::check
    absl::status
    absl::strings
    GTest::gmock_main
)

fuzztest_cc_library(
  NAME
    logging
  HDRS
    "internal/logging.h"
  SRCS
    "internal/logging.cc"
  DEPS
    absl::strings
)

fuzztest_cc_library(
  NAME
    meta
  HDRS
    "internal/meta.h"
  DEPS
    absl::int128
)

fuzztest_cc_library(
  NAME
    printer
  HDRS
    "internal/printer.h"
  DEPS
    fuzztest::meta
    absl::str_format
)

fuzztest_cc_library(
  NAME
    regexp_dfa
  HDRS
    "internal/domains/regexp_dfa.h"
  SRCS
    "internal/domains/regexp_dfa.cc"
  DEPS
    fuzztest::logging
    absl::flat_hash_map
    absl::random_bit_gen_ref
    absl::random_distributions
    absl::status
    absl::statusor
    absl::strings
    re2::re2
)

fuzztest_cc_library(
  NAME
    registration
  HDRS
    "internal/registration.h"
  DEPS
    fuzztest::domain_core
    fuzztest::meta
    fuzztest::printer
    fuzztest::type_support
    absl::any_invocable
    absl::status
    absl::str_format
    absl::span
)

fuzztest_cc_library(
  NAME
    registry
  HDRS
    "internal/registry.h"
  SRCS
    "internal/registry.cc"
  DEPS
    fuzztest::compatibility_mode
    fuzztest::fixture_driver
    fuzztest::registration
    fuzztest::runtime
    absl::flat_hash_map
    absl::function_ref
    absl::string_view
)

fuzztest_cc_library(
  NAME
    runtime
  HDRS
    "internal/runtime.h"
  SRCS
    "internal/runtime.cc"
  DEPS
    fuzztest::configuration
    fuzztest::corpus_database
    fuzztest::coverage
    fuzztest::domain_core
    fuzztest::fixture_driver
    fuzztest::io
    fuzztest::logging
    fuzztest::printer
    fuzztest::registration
    fuzztest::seed_seq
    fuzztest::serialization
    fuzztest::status
    absl::any_invocable
    absl::bind_front
    absl::function_ref
    absl::check
    absl::random_random
    absl::random_bit_gen_ref
    absl::random_distributions
    absl::status
    absl::statusor
    absl::strings
    absl::str_format
    absl::time
    absl::span
)

fuzztest_cc_test(
  NAME
    runtime_test
  SRCS
    "internal/runtime_test.cc"
  DEPS
    fuzztest::domain_core
    fuzztest::runtime
    test_protobuf
    absl::time
    GTest::gmock_main
)

fuzztest_cc_library(
  NAME
    seed_seq
  HDRS
    "internal/seed_seq.h"
  SRCS
    "internal/seed_seq.cc"
  DEPS
    fuzztest::logging
    absl::random_random
    absl::strings
    absl::span
)

fuzztest_cc_test(
  NAME
    seed_seq_test
  SRCS
    "internal/seed_seq_test.cc"
  DEPS
    fuzztest::seed_seq
    absl::strings
    absl::span
    GTest::gmock_main
)

fuzztest_cc_library(
  NAME
    serialization
  HDRS
    "internal/serialization.h"
  SRCS
    "internal/serialization.cc"
  DEPS
    fuzztest::meta
    absl::int128
    absl::strings
    absl::str_format
    absl::span
)

fuzztest_cc_test(
  NAME
    serialization_test
  SRCS
    "internal/serialization_test.cc"
  DEPS
    fuzztest::serialization
    test_protobuf
    GTest::gmock_main
    protobuf::libprotobuf
)

fuzztest_cc_library(
  NAME
    status
  HDRS
    "internal/status.h"
  SRCS
    "internal/status.cc"
  DEPS
    absl::status
    absl::strings
    absl::cord
)

fuzztest_cc_library(
  NAME
    subprocess
  HDRS
    "internal/subprocess.h"
  SRCS
    "internal/subprocess.cc"
  DEPS
    fuzztest::logging
    absl::flat_hash_map
    absl::strings
    absl::time
)

fuzztest_cc_test(
  NAME
    subprocess_test
  SRCS
    "internal/subprocess_test.cc"
  DEPS
    fuzztest::subprocess
    absl::strings
    absl::time
    GTest::gmock_main
)

fuzztest_cc_library(
  NAME
    table_of_recent_compares
  HDRS
    "internal/table_of_recent_compares.h"
  DEPS
    fuzztest::type_support
    absl::flat_hash_set
    absl::random_bit_gen_ref
    absl::random_distributions
)

fuzztest_cc_test(
  NAME
    table_of_recent_compares_test
  SRCS
    "internal/table_of_recent_compares_test.cc"
  DEPS
    fuzztest::table_of_recent_compares
    absl::random_random
    GTest::gmock_main
)

# TODO(lszekeres): Support fuzztest_cc_proto_library.

if (FUZZTEST_BUILD_TESTING)

  include_directories(${PROTOBUF_INCLUDE_DIR})

  add_library(
    test_protobuf
    OBJECT
    "${CMAKE_CURRENT_LIST_DIR}/internal/test_protobuf.proto"
  )
  target_link_libraries(
    test_protobuf
    PUBLIC
    protobuf::libprotobuf
  )

  # The output dir of `test_protobuf` might not be created by `protobuf_generate`.
  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/internal)

  protobuf_generate(
    TARGET
      test_protobuf
    IMPORT_DIRS
      ${CMAKE_CURRENT_LIST_DIR}/internal
    PROTOC_OUT_DIR
      ${CMAKE_CURRENT_BINARY_DIR}/internal
  )

  target_include_directories(
    test_protobuf
    PUBLIC
    "${CMAKE_CURRENT_BINARY_DIR}/.."
  )

endif ()

fuzztest_cc_library(
  NAME
    type_support
  HDRS
    "internal/type_support.h"
  SRCS
    "internal/type_support.cc"
  DEPS
    fuzztest::absl_helpers
    fuzztest::meta
    fuzztest::printer
    absl::function_ref
    absl::symbolize
    absl::int128
    absl::strings
    absl::str_format
    absl::time
)

fuzztest_cc_test(
  NAME
    type_support_test
  SRCS
    "internal/type_support_test.cc"
  DEPS
    fuzztest::domain
    fuzztest::meta
    fuzztest::printer
    test_protobuf
    fuzztest::type_support
    absl::int128
    absl::strings
    absl::str_format
    absl::time
    GTest::gmock_main
)
