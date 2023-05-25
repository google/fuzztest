cmake_minimum_required(VERSION 3.19)
project(escaping_test)
set(CMAKE_CXX_STANDARD 17)

# Remove ../../ in real examples.
add_subdirectory(../../fuzztest fuzztest)

enable_testing()
include(GoogleTest)

fuzztest_setup_fuzzing_flags()

add_library(escaping
  OBJECT
  escaping.cc
  escaping.h
)

add_executable(
  escaping_test
  escaping_test.cc
)

target_link_libraries(
  escaping_test
  PRIVATE
  escaping
)

link_fuzztest(escaping_test)
gtest_discover_tests(escaping_test)

