get_filename_component(PARENT_DIR ../ ABSOLUTE)
include_directories(${PARENT_DIR})

add_subdirectory(testdata)

add_executable(
  functional_test
  functional_test.cc
)
target_link_libraries(
  functional_test
  PUBLIC
  fuzztest_io
  fuzztest_logging
  fuzztest_serialization
  fuzztest_subprocess
  fuzztest_type_support
  re2
  absl::flat_hash_map
  absl::strings
  absl::str_format
  absl::time
  GTest::gmock_main
)
add_test(
  NAME
  functional_test
  COMMAND
  functional_test --test_srcdir="${CMAKE_BINARY_DIR}"
)
set_property(
  TEST
  functional_test
  PROPERTY ENVIRONMENT
  "TEST_SRCDIR=${CMAKE_BINARY_DIR}"
)

add_executable(
  benchmark_test
  benchmark_test.cc
)
target_link_libraries(
  benchmark_test
  PUBLIC
  fuzztest_logging
  fuzztest_subprocess
  re2
  absl::flat_hash_map
  absl::flags
  absl::flags_parse
  absl::strings
  absl::str_format
  absl::time
  GTest::gmock_main
)
