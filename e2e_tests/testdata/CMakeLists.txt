get_filename_component(PARENT_DIR ../ ABSOLUTE)
include_directories(${PARENT_DIR})

include_directories(${CMAKE_BINARY_DIR})
add_executable(
  fuzz_tests_for_microbenchmarking
  fuzz_tests_for_microbenchmarking.cc
)
target_link_libraries(
  fuzz_tests_for_microbenchmarking
  PUBLIC
  fuzztest_status
  protobuf::libprotobuf
  test_protobuf
)
link_fuzztest(fuzz_tests_for_microbenchmarking)

add_executable(
  fuzz_tests_for_functional_testing.stripped
  fuzz_tests_for_functional_testing.cc
  fuzz_tests_for_microbenchmarking.cc
  fuzz_tests_using_googletest.cc
)
target_link_libraries(
  fuzz_tests_for_functional_testing.stripped
  PUBLIC
  protobuf::libprotobuf
  test_protobuf
  absl::function_ref
  absl::str_format
  absl::time
  fuzztest_googletest_fixture_adapter
  fuzztest_status
)
link_fuzztest(fuzz_tests_for_functional_testing.stripped)
set_target_properties(
  fuzz_tests_for_functional_testing.stripped
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY
  "${CMAKE_BINARY_DIR}/com_google_fuzztest/e2e_tests/testdata"
)

add_executable(
  fuzz_tests_with_invalid_seeds.stripped
  fuzz_tests_with_invalid_seeds.cc
)
target_link_libraries(
  fuzz_tests_with_invalid_seeds.stripped
  PUBLIC
  fuzztest_status
)
link_fuzztest(fuzz_tests_with_invalid_seeds.stripped)
set_target_properties(
  fuzz_tests_with_invalid_seeds.stripped
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY
  "${CMAKE_BINARY_DIR}/com_google_fuzztest/e2e_tests/testdata"
)
