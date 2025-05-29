
add_library(
  grammar_info
  INTERFACE
  grammar_info.h
)

add_library(
  antlr_frontend
  STATIC
  antlr_frontend.cc
  antlr_frontend.h
)

target_link_libraries(
  antlr_frontend
  PUBLIC
  grammar_info
  absl::str_format
  absl::strings
  fuzztest_logging
  generated_antlr_parser
)

add_library(
  backend
  OBJECT
  backend.cc
  backend.h
)

target_link_libraries(
  backend
  PUBLIC
  absl::btree
  absl::flat_hash_set
  absl::strings
  absl::str_format
  fuzztest_logging
)

add_library(
  code_generation
  STATIC
  code_generation.cc
  code_generation.h
)

target_link_libraries(
  code_generation
  PUBLIC
  antlr_frontend
  backend
)

target_include_directories(
  code_generation
  PUBLIC
  ${PARENT_DIR}
)

# TODO(changochen): Enable the test if we can figure out how to specify the path.
#if (FUZZTEST_BUILD_TESTING)
#  add_executable(
#    code_generation_test
#    code_generation_test.cc
#  )
#  target_link_libraries(
#    code_generation_test
#    PUBLIC
#    code_generation
#    absl::strings
#    GTest::gmock_main
#  )
#  add_test(
#    NAME
#    code_generation_test
#    COMMAND
#    code_generation_test
#  )
#endif ()
