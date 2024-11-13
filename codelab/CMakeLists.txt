cmake_minimum_required(VERSION 3.19)
project(escaping_test)
set(CMAKE_CXX_STANDARD 17)

include(FetchContent)

set(FUZZTEST_REPO "google/fuzztest" CACHE STRING "FuzzTest repository." )
set(FUZZTEST_REPO_BRANCH "main" CACHE STRING "FuzzTest repository branch.")
message("Building fuzztest from ${FUZZTEST_REPO} at branch ${FUZZTEST_REPO_BRANCH}")

FetchContent_Declare(
  fuzztest
  GIT_REPOSITORY https://github.com/${FUZZTEST_REPO}.git
  GIT_TAG ${FUZZTEST_REPO_BRANCH}
)

FetchContent_MakeAvailable(fuzztest)

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

