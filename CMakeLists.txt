cmake_minimum_required(VERSION 3.19)
project(fuzztest)

option(FUZZTEST_BUILD_TESTING "Building the tests." OFF)
option(FUZZTEST_FUZZING_MODE "Building the fuzztest in fuzzing mode." OFF)
set(FUZZTEST_COMPATIBILITY_MODE "" CACHE STRING "Compatibility mode. Available options: <empty>, libfuzzer")
set(CMAKE_CXX_STANDARD 17)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set (COMPILER_GCC 1)
elseif (CMAKE_CXX_COMPILER_ID MATCHES "AppleClang")
  set (COMPILER_CLANG 1) # Safe to treat AppleClang as a regular Clang, in general.
elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set (COMPILER_CLANG 1)
else ()
  message (FATAL_ERROR "Compiler ${CMAKE_CXX_COMPILER_ID} is not supported")
endif ()

if (COMPILER_GCC AND (FUZZTEST_FUZZING_MODE OR (FUZZTEST_COMPATIBILITY_MODE STREQUAL "libfuzzer")))
  message (FATAL_ERROR "Compilation with GCC is not yet supported for fuzztest mode. Please use Clang. CC=clang CXX=clang++")
endif ()

if (FUZZTEST_FUZZING_MODE AND NOT FUZZTEST_COMPATIBILITY_MODE STREQUAL "")
  message (FATAL_ERROR "Please either use fuzzing mode or compatibility mode")
endif ()

if (NOT FUZZTEST_COMPATIBILITY_MODE STREQUAL "" AND
    NOT FUZZTEST_COMPATIBILITY_MODE STREQUAL "libfuzzer")
  message (FATAL_ERROR "Compatibility mode is only supported for libfuzzer")
endif ()

include(cmake/AddFuzzTest.cmake)
include(cmake/FuzzTestFlagSetup.cmake)

fuzztest_setup_fuzzing_flags()

include(cmake/BuildDependencies.cmake)
include(cmake/FuzzTestHelpers.cmake)

include_directories(${re2_SOURCE_DIR})

if (FUZZTEST_BUILD_TESTING)
  enable_testing()
endif ()

if (FUZZTEST_BUILD_TESTING)
  set(protobuf_PROTOC_EXE "${protobuf_BINARY_DIR}/protoc")
  include(${protobuf_SOURCE_DIR}/cmake/protobuf-generate.cmake)
endif ()

add_subdirectory(grammar_codegen)
add_subdirectory(tools)
add_subdirectory(common)
add_subdirectory(fuzztest)

if (FUZZTEST_BUILD_TESTING)
  add_subdirectory(domain_tests)
  add_subdirectory(e2e_tests)
endif ()
