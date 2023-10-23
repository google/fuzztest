get_filename_component(PARENT_DIR ../ ABSOLUTE)
include_directories(${PARENT_DIR})

add_subdirectory(grammars)

if (FUZZTEST_TESTING)
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

# TODO: introduce similar functions to absl_cc_library and absl_cc_test to ease
# the automation of synchronization.
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize-coverage=0")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize-coverage=0")

add_library(
  fuzztest_logging
  OBJECT
  internal/logging.cc
  internal/logging.h
)

target_link_libraries(
  fuzztest_logging
  PUBLIC
  absl::strings
)

add_library(
  fuzztest_meta
  OBJECT
  internal/meta.h
)

set_target_properties(
  fuzztest_meta
  PROPERTIES
  LINKER_LANGUAGE
  CXX
)
target_link_libraries(
  fuzztest_meta
  PUBLIC
  absl::int128
)

add_library(
  fuzztest_any
  OBJECT
  internal/any.h
)
set_target_properties(
  fuzztest_any
  PROPERTIES
  LINKER_LANGUAGE CXX
)
target_link_libraries(
  fuzztest_any
  PUBLIC
  fuzztest_meta
  fuzztest_logging
)

if (FUZZTEST_TESTING)
  add_executable(
    fuzztest_any_test
    internal/any_test.cc
  )
  target_link_libraries(fuzztest_any_test PUBLIC
    fuzztest_any
    fuzztest_logging
    absl::strings
    GTest::gtest_main
  )
  add_test(
    NAME
    fuzztest_any_test
    COMMAND
    fuzztest_any_test
  )
endif()

add_library(
  fuzztest_type_support
  OBJECT
  internal/type_support.cc
  internal/type_support.h
)

target_link_libraries(
  fuzztest_type_support
  PUBLIC
  fuzztest_meta
  absl::symbolize
  absl::strings
  absl::str_format
)

if (FUZZTEST_TESTING)
  add_executable(
    fuzztest_type_support_test
    internal/type_support_test.cc
  )
  target_link_libraries(
    fuzztest_type_support_test
    PUBLIC
    fuzztest_domain
    fuzztest_fixture_driver
    fuzztest_registration
    fuzztest_logging
    fuzztest_coverage
    fuzztest_status
    fuzztest_type_support
    protobuf::libprotobuf
    test_protobuf
    absl::span
    GTest::gmock_main
  )
  add_test(
    NAME
    fuzztest_type_support_test
    COMMAND
    fuzztest_type_support_test
  )
endif()

add_library(
  fuzztest_table_of_recent_compares
  OBJECT
  internal/table_of_recent_compares.h
)

set_target_properties(
  fuzztest_table_of_recent_compares
  PROPERTIES
  LINKER_LANGUAGE CXX
)
target_link_libraries(
  fuzztest_table_of_recent_compares
  PUBLIC
  fuzztest_type_support
  absl::flat_hash_set
  absl::random_distributions
)

if (FUZZTEST_TESTING)
  add_executable(
    fuzztest_table_of_recent_compares_test
    internal/table_of_recent_compares_test.cc
  )
  target_link_libraries(
    fuzztest_table_of_recent_compares_test
    PUBLIC
    fuzztest_domain
    absl::random_random
    GTest::gmock_main
  )
  add_test(
    NAME
    fuzztest_table_of_recent_compares_test
    COMMAND
    fuzztest_table_of_recent_compares_test
  )
endif()

add_library(
  fuzztest_regexp_dfa
  OBJECT
  internal/domains/regexp_dfa.cc
  internal/domains/regexp_dfa.h
)

target_link_libraries(
  fuzztest_regexp_dfa
  PUBLIC
  fuzztest_logging
  absl::flat_hash_map
  absl::random_distributions
  re2::re2
)

add_library(
  fuzztest_io
  OBJECT
  internal/io.cc
  internal/io.h
)

target_link_libraries(
  fuzztest_io
  PUBLIC
  fuzztest_logging
  absl::hash
  absl::str_format
)

if (FUZZTEST_TESTING)
  add_executable(
    fuzztest_io_test
    internal/io_test.cc
  )
  target_link_libraries(
    fuzztest_io_test
    PUBLIC
    fuzztest_io
    fuzztest_fuzztest
    fuzztest_registry
    fuzztest_logging
    absl::strings
    GTest::gmock_main
  )
  add_test(
    NAME
    fuzztest_io_test
    COMMAND
    fuzztest_io_test
  )
endif()

add_library(
  fuzztest_coverage
  OBJECT
  internal/coverage.cc
  internal/coverage.h
)

target_link_libraries(
  fuzztest_coverage
  PUBLIC
  fuzztest_logging
  fuzztest_table_of_recent_compares
  absl::base
  absl::span
)

add_library(
  fuzztest_registration
  OBJECT
  internal/registration.h
)
set_target_properties(
  fuzztest_registration
  PROPERTIES
  LINKER_LANGUAGE CXX
)
target_link_libraries(
  fuzztest_registration
  PUBLIC
  fuzztest_domain
  fuzztest_meta
  fuzztest_status
  fuzztest_type_support
  absl::any_invocable
  absl::str_format
  absl::span
)

add_library(
  fuzztest_fixture_driver
  OBJECT
  internal/fixture_driver.h
  internal/fixture_driver.cc
)

target_link_libraries(
  fuzztest_fixture_driver
  PUBLIC
  fuzztest_any
  fuzztest_domain
  fuzztest_logging
  fuzztest_registration
  fuzztest_type_support
  fuzztest_status
  absl::memory
  absl::str_format
  absl::span
)

if (FUZZTEST_TESTING)
  add_executable(
    fuzztest_fixture_driver_test
    internal/fixture_driver_test.cc
  )
  target_link_libraries(
    fuzztest_fixture_driver_test
    PUBLIC
    fuzztest_any
    fuzztest_domain
    fuzztest_fixture_driver
    fuzztest_registration
    fuzztest_logging
    fuzztest_coverage
    fuzztest_status
    fuzztest_type_support
    absl::span
    GTest::gmock_main
  )
  add_test(
    NAME
    fuzztest_fixture_driver_test
    COMMAND
    fuzztest_fixture_driver_test
  )
endif()

add_library(
  fuzztest_serialization
  OBJECT
  internal/serialization.cc
  internal/serialization.h
)

target_link_libraries(
  fuzztest_serialization
  PUBLIC
  fuzztest_meta
  absl::int128
  absl::strings
  absl::str_format
  absl::span
  absl::variant
)

if (FUZZTEST_TESTING)
  add_executable(
    fuzztest_serialization_test
    internal/serialization_test.cc
  )
  target_link_libraries(
    fuzztest_serialization_test
    PUBLIC
    fuzztest_logging
    fuzztest_domain
    fuzztest_coverage
    fuzztest_seed_seq
    fuzztest_fixture_driver
    fuzztest_serialization
    fuzztest_status
    fuzztest_io
    fuzztest_type_support
    protobuf::libprotobuf
    fuzztest_runtime
    absl::time
    test_protobuf
    GTest::gmock_main
  )
  add_test(
    NAME
    fuzztest_serialization_test
    COMMAND
    fuzztest_serialization_test
  )
endif ()

add_library(
  fuzztest_status
  OBJECT
  internal/status.cc
  internal/status.h
)

target_link_libraries(
  fuzztest_status
  PUBLIC
  absl::cord
  absl::status
  absl::strings
)

add_library(
  fuzztest_subprocess
  OBJECT
  internal/subprocess.cc
  internal/subprocess.h
)

target_link_libraries(
  fuzztest_subprocess
  PUBLIC
  fuzztest_logging
  absl::flat_hash_map
  absl::strings
  absl::time
)

if (FUZZTEST_TESTING)
  add_executable(
    fuzztest_subprocess_test
    internal/subprocess_test.cc
  )
  target_link_libraries(
    fuzztest_subprocess_test
    PUBLIC
    fuzztest_logging
    fuzztest_subprocess
    absl::strings
    absl::time
    GTest::gmock_main
  )
  add_test(
    NAME
    fuzztest_subprocess_test
    COMMAND
    fuzztest_subprocess_test
  )
endif ()

add_library(
  fuzztest_domain
  OBJECT
  internal/domains/in_grammar_impl.cc
  domain.h
  domain_core.h
  internal/domains/aggregate_of_impl.h
  internal/domains/arbitrary_impl.h
  internal/domains/bit_flag_combination_of_impl.h
  internal/domains/container_mutation_helpers.h
  internal/domains/container_of_impl.h
  internal/domains/domain_base.h
  internal/domains/element_of_impl.h
  internal/domains/filter_impl.h
  internal/domains/flat_map_impl.h
  internal/domains/in_grammar_impl.h
  internal/domains/in_range_impl.h
  internal/domains/in_regexp_impl.h
  internal/domains/map_impl.h
  internal/domains/one_of_impl.h
  internal/domains/optional_of_impl.h
  internal/domains/protobuf_domain_impl.h
  internal/domains/serialization_helpers.h
  internal/domains/smart_pointer_of_impl.h
  internal/domains/unique_elements_container_of_impl.h
  internal/domains/value_mutation_helpers.h
  internal/domains/variant_of_impl.h
)

target_link_libraries(
  fuzztest_domain
  PUBLIC
  fuzztest_coverage
  fuzztest_logging
  fuzztest_meta
  fuzztest_regexp_dfa
  fuzztest_serialization
  fuzztest_status
  fuzztest_table_of_recent_compares
  fuzztest_type_support
  absl::base
  absl::bits
  absl::flat_hash_map
  absl::flat_hash_set
  absl::int128
  absl::random_distributions
  absl::span
  absl::status
  absl::str_format
  absl::strings
  absl::synchronization
)

add_library(
  fuzztest_seed_seq
  OBJECT
  internal/seed_seq.cc
  internal/seed_seq.h
)

target_link_libraries(
  fuzztest_seed_seq
  PUBLIC
  fuzztest_logging
  absl::strings
  absl::random_random
  absl::span
)

if (FUZZTEST_TESTING)
  add_executable(
    fuzztest_seed_seq_test
    internal/seed_seq_test.cc
  )
  target_link_libraries(
    fuzztest_seed_seq_test
    PUBLIC
    fuzztest_logging
    fuzztest_domain
    fuzztest_coverage
    fuzztest_seed_seq
    fuzztest_fixture_driver
    fuzztest_serialization
    fuzztest_io
    fuzztest_type_support
    fuzztest_runtime
    fuzztest_status
    absl::time
    GTest::gmock_main
  )
  add_test(
    NAME
    fuzztest_seed_seq_test
    COMMAND
    fuzztest_seed_seq_test
  )
endif ()

add_library(
  fuzztest_runtime
  OBJECT
  internal/runtime.cc
  internal/runtime.h
)

target_link_libraries(
  fuzztest_runtime
  PUBLIC
  fuzztest_coverage
  fuzztest_domain
  fuzztest_fixture_driver
  fuzztest_io
  fuzztest_logging
  fuzztest_meta
  fuzztest_registration
  fuzztest_status
  fuzztest_serialization
  fuzztest_type_support
  absl::any_invocable
  absl::function_ref
  absl::random_random
  absl::random_seed_sequences
  absl::status
  absl::strings
  absl::str_format
  absl::time
  absl::span
)

if (FUZZTEST_TESTING)
  add_executable(
    fuzztest_runtime_test
    internal/runtime_test.cc
  )
  target_link_libraries(
    fuzztest_runtime_test
    PUBLIC
    fuzztest_logging
    fuzztest_domain
    fuzztest_coverage
    fuzztest_seed_seq
    fuzztest_fixture_driver
    fuzztest_serialization
    fuzztest_io
    fuzztest_type_support
    fuzztest_runtime
    fuzztest_status
    absl::time
    test_protobuf
    GTest::gtest_main
  )
  add_test(
    NAME
    fuzztest_runtime_test
    COMMAND
    fuzztest_runtime_test
  )
endif ()

add_library(
  fuzztest_compatibility_mode
  OBJECT
  internal/compatibility_mode.cc
  internal/compatibility_mode.h
)

target_link_libraries(
  fuzztest_compatibility_mode
  PUBLIC
  fuzztest_fixture_driver
  fuzztest_logging
  fuzztest_runtime
  absl::random_distributions
  absl::strings
  absl::str_format
  absl::time
)

add_library(
  fuzztest_registry
  OBJECT
  internal/registry.cc
  internal/registry.h
)

target_link_libraries(
  fuzztest_registry
  PUBLIC
  fuzztest_compatibility_mode
  fuzztest_fixture_driver
  fuzztest_registration
  fuzztest_runtime
  absl::flat_hash_map
  absl::function_ref
  absl::string_view
)

add_library(
  fuzztest_fuzztest
  OBJECT
  fuzztest.cc
  fuzztest.h
)

target_link_libraries(
  fuzztest_fuzztest
  PUBLIC
  fuzztest_domain
  fuzztest_io
  fuzztest_registry
  fuzztest_runtime
  absl::str_format
  absl::strings
)
target_include_directories(
    fuzztest_fuzztest
    SYSTEM INTERFACE
    "$<BUILD_INTERFACE:${fuzztest_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}>")

if (FUZZTEST_USE_GTEST OR FUZZTEST_TESTING)
  add_library(
    fuzztest_init_fuzztest
    OBJECT
    init_fuzztest.cc
    init_fuzztest.h
  )

  target_link_libraries(
    fuzztest_init_fuzztest
    PUBLIC
    absl::flags
    absl::strings
    absl::time
    fuzztest_googletest_adaptor
    fuzztest_runtime
    GTest::gtest
  )

  add_library(
    fuzztest_googletest_adaptor
    OBJECT
    internal/googletest_adaptor.cc
    internal/googletest_adaptor.h
  )

  target_link_libraries(
    fuzztest_googletest_adaptor
    PUBLIC
    fuzztest_registry
    fuzztest_runtime
    GTest::gtest
  )

  add_library(
    fuzztest_googletest_fixture_adapter
    OBJECT
    googletest_fixture_adapter.h
  )

  target_link_libraries(
    fuzztest_googletest_fixture_adapter
    PUBLIC
    fuzztest_fixture_driver
    GTest::gtest
  )

  add_library(
    fuzztest_gtest_main
    STATIC
    fuzztest_gtest_main.cc
  )

  target_link_libraries(
    fuzztest_gtest_main
    PUBLIC
    fuzztest_serialization
    fuzztest_init_fuzztest
    fuzztest_io
    fuzztest_coverage
    fuzztest_logging
    fuzztest_fixture_driver
    fuzztest_type_support
    fuzztest_seed_seq
    fuzztest_fuzztest
    fuzztest_registry
    fuzztest_googletest_adaptor
    fuzztest_regexp_dfa
    fuzztest_runtime
    fuzztest_table_of_recent_compares
    fuzztest_subprocess
    fuzztest_status
    fuzztest_compatibility_mode
    absl::flags_parse
    GTest::gtest
    GTest::gmock
  )
  # Make sure the headers are available.
  target_include_directories(
    fuzztest_gtest_main
    SYSTEM INTERFACE
    "$<BUILD_INTERFACE:${fuzztest_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}>")
endif ()
