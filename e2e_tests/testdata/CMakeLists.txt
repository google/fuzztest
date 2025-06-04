add_executable(
  fuzz_tests_for_microbenchmarking
  fuzz_tests_for_microbenchmarking.cc
)
target_link_libraries(
  fuzz_tests_for_microbenchmarking
  PUBLIC
  fuzztest_status
  protobuf::libprotobuf
  fuzztest::test_protobuf_cc_proto
  absl::random_bit_gen_ref
  absl::random_distributions
  absl::str_format
  absl::string_view
)
link_fuzztest(fuzz_tests_for_microbenchmarking)

add_executable(
  fuzz_tests_for_functional_testing.stripped
  fuzz_tests_for_functional_testing.cc
  fuzz_tests_for_microbenchmarking.cc
  fuzz_tests_using_googletest.cc
  fuzz_tests_with_proto_inputs.cc
)
target_link_libraries(
  fuzz_tests_for_functional_testing.stripped
  PUBLIC
  protobuf::libprotobuf
  fuzztest::test_protobuf_cc_proto
  absl::algorithm_container
  absl::check
  absl::flat_hash_map
  absl::flat_hash_set
  absl::function_ref
  absl::random_bit_gen_ref
  absl::random_distributions
  absl::span
  absl::str_format
  absl::strings
  absl::time
  re2::re2
  fuzztest_googletest_fixture_adapter
  fuzztest_logging
)
link_fuzztest(fuzz_tests_for_functional_testing.stripped)
set_target_properties(
  fuzz_tests_for_functional_testing.stripped
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY
  "${CMAKE_BINARY_DIR}/_main/e2e_tests/testdata"
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
  "${CMAKE_BINARY_DIR}/_main/e2e_tests/testdata"
)

add_executable(
  dynamically_registered_fuzz_tests.stripped
  dynamically_registered_fuzz_tests.cc
)
link_fuzztest(dynamically_registered_fuzz_tests.stripped)
set_target_properties(
  dynamically_registered_fuzz_tests.stripped
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY
  "${CMAKE_BINARY_DIR}/_main/e2e_tests/testdata"
)

add_executable(
  unit_test_and_fuzz_tests.stripped
  unit_test_and_fuzz_tests.cc
)
link_fuzztest(unit_test_and_fuzz_tests.stripped)
set_target_properties(
  unit_test_and_fuzz_tests.stripped
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY
  "${CMAKE_BINARY_DIR}/_main/e2e_tests/testdata"
)

add_executable(
  fuzz_tests_for_corpus_database_testing.stripped
  fuzz_tests_for_corpus_database_testing.cc
)
link_fuzztest(fuzz_tests_for_corpus_database_testing.stripped)
set_target_properties(
  fuzz_tests_for_corpus_database_testing.stripped
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY
  "${CMAKE_BINARY_DIR}/_main/e2e_tests/testdata"
)

add_executable(
  llvm_fuzzer_with_custom_mutator.stripped
  llvm_fuzzer_with_custom_mutator.cc
)
target_link_libraries(
  llvm_fuzzer_with_custom_mutator.stripped
  PRIVATE
  fuzztest::llvm_fuzzer_main
  fuzztest::llvm_fuzzer_wrapper
)
set_target_properties(
  llvm_fuzzer_with_custom_mutator.stripped
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY
  "${CMAKE_BINARY_DIR}/_main/e2e_tests/testdata"
)
