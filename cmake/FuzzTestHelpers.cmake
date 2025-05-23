# Copyright 2023 Google LLC
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

include(CMakeParseArguments)

# fuzztest_cc_library()
#
# CMake function to imitate Bazel's cc_library rule.
#
# Parameters:
#
#   NAME: Name of target (see Note)
#   HDRS: List of public header files for the library
#   SRCS: List of source files for the library
#   DEPS: List of other libraries to be linked in to the binary targets
#   COPTS: List of private compile options
#   DEFINES: List of public defines
#   LINKOPTS: List of link options
#   PUBLIC: Add this so that this library will be exported under fuzztest::
#   TESTONLY: When added, this target will only be built if both
#             BUILD_TESTING=ON and FUZZTEST_BUILD_TESTING=ON.
#
# Note:
#
#   By default, fuzztest_cc_library will always create a library named
#   fuzztest_${NAME}, and alias target fuzztest::${NAME}. The fuzztest:: form
#   should always be used. This is to reduce namespace pollution.
#
# Usage:
#
#   fuzztest_cc_library(
#     NAME
#       awesome
#     HDRS
#       "a.h"
#     SRCS
#       "a.cc"
#   )
#   fuzztest_cc_library(
#     NAME
#       fantastic_lib
#     SRCS
#       "b.cc"
#     DEPS
#       fuzztest::awesome # not "awesome" !
#     PUBLIC
#   )
#
#   fuzztest_cc_library(
#     NAME
#       main_lib
#     ...
#     DEPS
#       fuzztest::fantastic_lib
#   )
#
function(fuzztest_cc_library)
  cmake_parse_arguments(
    FUZZTEST_CC_LIB
    "PUBLIC;TESTONLY"
    "NAME"
    "HDRS;SRCS;COPTS;DEFINES;LINKOPTS;DEPS"
    ${ARGN}
  )

  if(FUZZTEST_CC_LIB_TESTONLY AND NOT (BUILD_TESTING AND FUZZTEST_BUILD_TESTING))
    return()
  endif()

  set(_NAME "fuzztest_${FUZZTEST_CC_LIB_NAME}")

  # Check if this is a header-only library
  # TODO: Use list(FILTER...)
  set(FUZZTEST_CC_SRCS "${FUZZTEST_CC_LIB_SRCS}")
  foreach(src_file IN LISTS FUZZTEST_CC_SRCS)
    if(${src_file} MATCHES ".*\\.(h|inc)")
      list(REMOVE_ITEM FUZZTEST_CC_SRCS "${src_file}")
    endif()
  endforeach()

  if(FUZZTEST_CC_SRCS STREQUAL "")
    set(FUZZTEST_CC_LIB_IS_INTERFACE 1)
  else()
    set(FUZZTEST_CC_LIB_IS_INTERFACE 0)
  endif()

  if(NOT FUZZTEST_CC_LIB_IS_INTERFACE)

    add_library(${_NAME} "")

    target_sources(
      ${_NAME}
      PRIVATE
      ${FUZZTEST_CC_LIB_SRCS}
      ${FUZZTEST_CC_LIB_HDRS}
    )

    target_link_libraries(
      ${_NAME}
      PUBLIC
      ${FUZZTEST_CC_LIB_DEPS}
      PRIVATE
      ${FUZZTEST_CC_LIB_LINKOPTS}
      ${FUZZTEST_DEFAULT_LINKOPTS}
    )

    set_property(
      TARGET ${_NAME}
      PROPERTY LINKER_LANGUAGE "CXX")

    target_include_directories(
      ${_NAME}
      PUBLIC
      "$<BUILD_INTERFACE:${fuzztest_SOURCE_DIR}>"
      "$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}>"
    )

    target_compile_options(
      ${_NAME}
      PRIVATE
      ${FUZZTEST_CC_LIB_COPTS}
    )

    target_compile_definitions(
      ${_NAME}
      PUBLIC
      ${FUZZTEST_CC_LIB_DEFINES}
    )

  else()

    # Header-only library.

    add_library(
      ${_NAME}
      INTERFACE
    )

    target_include_directories(
      ${_NAME}
      INTERFACE
      "$<BUILD_INTERFACE:${fuzztest_SOURCE_DIR}>"
      "$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}>"
      )

    target_link_libraries(
      ${_NAME}
      INTERFACE
      ${FUZZTEST_CC_LIB_DEPS}
      ${FUZZTEST_CC_LIB_LINKOPTS}
      ${FUZZTEST_DEFAULT_LINKOPTS}
    )

   target_compile_definitions(
     ${_NAME}
     INTERFACE
     ${FUZZTEST_CC_LIB_DEFINES})

  endif()

    add_library(fuzztest::${FUZZTEST_CC_LIB_NAME} ALIAS ${_NAME})

endfunction()

# fuzztest_cc_test()
#
# CMake function to imitate Bazel's cc_test rule.
#
# Parameters:
#
#   NAME: name of target (see Usage below)
#   SRCS: List of source files for the binary
#   DEPS: List of other libraries to be linked in to the binary targets
#   COPTS: List of private compile options
#   DEFINES: List of public defines
#   LINKOPTS: List of link options
#
# Note:
#
#   By default, fuzztest_cc_test will always create a binary named
#   fuzztest_${NAME}. This will also add it to ctest list as fuzztest_${NAME}.
#
# Usage:
#
#   fuzztest_cc_library(
#     NAME
#       awesome
#     HDRS
#       "a.h"
#     SRCS
#       "a.cc"
#     PUBLIC
#   )
#
#   fuzztest_cc_test(
#     NAME
#       awesome_test
#     SRCS
#       "awesome_test.cc"
#     DEPS
#       fuzztest::awesome
#       GTest::gmock
#       GTest::gtest_main
#   )
#
function(fuzztest_cc_test)
  if(NOT (BUILD_TESTING AND FUZZTEST_BUILD_TESTING))
    return()
  endif()

  cmake_parse_arguments(FUZZTEST_CC_TEST
    ""
    "NAME"
    "SRCS;COPTS;DEFINES;LINKOPTS;DEPS"
    ${ARGN}
  )

  set(_NAME "fuzztest_${FUZZTEST_CC_TEST_NAME}")

  add_executable(
    ${_NAME}
    ""
  )

  target_sources(
    ${_NAME}
    PRIVATE
    ${FUZZTEST_CC_TEST_SRCS}
  )

  target_include_directories(
    ${_NAME}
    PUBLIC
    "$<BUILD_INTERFACE:${fuzztest_SOURCE_DIR}>"
  )

  target_compile_definitions(
    ${_NAME}
    PUBLIC
    ${FUZZTEST_CC_TEST_DEFINES}
  )

  target_compile_options(
    ${_NAME}
    PRIVATE
    ${FUZZTEST_CC_TEST_COPTS}
  )

  target_link_libraries(
    ${_NAME}
    PUBLIC
    ${FUZZTEST_CC_TEST_DEPS}
    PRIVATE
    ${FUZZTEST_CC_TEST_LINKOPTS}
  )

  add_test(NAME ${_NAME} COMMAND ${_NAME})

endfunction()

# fuzztest_proto_library()
#
# CMake function to imitate Bazel's proto_library rule.
#
# Parameters:
#
#   NAME: Name of target (see Note)
#   SRCS: List of source files for the proto library
#   PUBLIC: Add this so that this library will be exported under fuzztest::
#   TESTONLY: When added, this target will only be built if both
#             BUILD_TESTING=ON and FUZZTEST_BUILD_TESTING=ON.
#
# Usage:
#
#   fuzztest_proto_library(
#     NAME
#       awesome_proto
#     SRCS
#       "awesome.proto"
#   )
#
# Reference:
#
#   https://github.com/protocolbuffers/protobuf/blob/main/docs/cmake_protobuf_generate.md
#
function(fuzztest_proto_library)
  cmake_parse_arguments(
    FUZZTEST_PROTO_LIB
    "PUBLIC;TESTONLY"
    "NAME"
    "SRCS"
    ${ARGN}
  )

  if(FUZZTEST_PROTO_LIB_TESTONLY AND NOT (BUILD_TESTING AND FUZZTEST_BUILD_TESTING))
    return()
  endif()

  set(_NAME "fuzztest_${FUZZTEST_PROTO_LIB_NAME}")

  add_library(
    ${_NAME}
    OBJECT
    ${FUZZTEST_PROTO_LIB_SRCS}
  )

  target_link_libraries(
    ${_NAME}
    PUBLIC
    protobuf::libprotobuf
  )

  target_include_directories(
    ${_NAME}
    PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}>"
  )

  protobuf_generate(
    TARGET
    ${_NAME}
    IMPORT_DIRS
    ${CMAKE_CURRENT_LIST_DIR}
    PROTOC_OUT_DIR
    ${CMAKE_CURRENT_BINARY_DIR}
  )

  add_library(fuzztest::${FUZZTEST_PROTO_LIB_NAME} ALIAS ${_NAME})

endfunction()