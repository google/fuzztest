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

# fuzztest_flatbuffers_generate_headers()
#
# Modified version of `flatbuffers_generate_headers`
# from https://github.com/google/flatbuffers/blob/master/CMake/BuildFlatBuffers.cmake
# Supports having the embedded schema header in the output set.
#
# Creates a target that can be linked against that generates flatbuffer headers.
#
# This function takes a target name and a list of schemas. You can also specify
# other flagc flags using the FLAGS option to change the behavior of the flatc
# tool.
#
# When the target_link_libraries is done within a different directory than
# flatbuffers_generate_headers is called, then the target should also be dependent
# the custom generation target called fuzztest_GENERATE_<TARGET>.
#
# Arguments:
#   TARGET: The name of the target to generate.
#   SCHEMAS: The list of schema files to generate code for.
#   BINARY_SCHEMAS_DIR: Optional. The directory in which to generate binary
#       schemas. Binary schemas will only be generated if a path is provided.
#   INCLUDE: Optional. Search for includes in the specified paths. (Use this
#       instead of "-I <path>" and the FLAGS option so that CMake is aware of
#       the directories that need to be searched).
#   INCLUDE_PREFIX: Optional. The directory in which to place the generated
#       files. Use this instead of the --include-prefix option.
#   FLAGS: Optional. A list of any additional flags that you would like to pass
#       to flatc.
#   TESTONLY: When added, this target will only be built if both
#             BUILD_TESTING=ON and FUZZTEST_BUILD_TESTING=ON.
#
# Example:
#
#     fuzztest_flatbuffers_library(
#         TARGET my_generated_headers_target
#         INCLUDE_PREFIX ${MY_INCLUDE_PREFIX}"
#         SCHEMAS ${MY_SCHEMA_FILES}
#         BINARY_SCHEMAS_DIR "${MY_BINARY_SCHEMA_DIRECTORY}"
#         FLAGS --gen-object-api)
#
#     target_link_libraries(MyExecutableTarget
#         PRIVATE fuzztest_my_generated_headers_target
#     )
#
# Optional (only needed within different directory):
#     add_dependencies(app fuzztest_GENERATE_my_generated_headers_target)
function(fuzztest_flatbuffers_generate_headers)
  # Parse function arguments.
  set(options TESTONLY)
  set(one_value_args
    "TARGET"
    "INCLUDE_PREFIX"
    "BINARY_SCHEMAS_DIR")
  set(multi_value_args
    "SCHEMAS"
    "INCLUDE"
    "FLAGS")
  cmake_parse_arguments(
    PARSE_ARGV 0
    FLATBUFFERS_GENERATE_HEADERS
    "${options}"
    "${one_value_args}"
    "${multi_value_args}")

  if(FLATBUFFERS_GENERATE_HEADERS_TESTONLY AND NOT (BUILD_TESTING AND FUZZTEST_BUILD_TESTING))
    return()
  endif()

  # Test if including from FindFlatBuffers
  if(FLATBUFFERS_FLATC_EXECUTABLE)
    set(FLATC_TARGET "")
    set(FLATC ${FLATBUFFERS_FLATC_EXECUTABLE})
  elseif(TARGET flatbuffers::flatc)
    set(FLATC_TARGET flatbuffers::flatc)
    set(FLATC flatbuffers::flatc)
  else()
    set(FLATC_TARGET flatc)
    set(FLATC flatc)
  endif()

  set(working_dir "${CMAKE_CURRENT_SOURCE_DIR}")

  # Generate the include files parameters.
  set(include_params "")
  foreach (include_dir ${FLATBUFFERS_GENERATE_HEADERS_INCLUDE})
    set(include_params -I ${include_dir} ${include_params})
  endforeach()

  # Create a directory to place the generated code.
  set(generated_target_dir "${CMAKE_CURRENT_BINARY_DIR}")
  set(generated_include_dir "${generated_target_dir}")
  if (NOT ${FLATBUFFERS_GENERATE_HEADERS_INCLUDE_PREFIX} STREQUAL "")
    set(generated_include_dir "${generated_include_dir}/${FLATBUFFERS_GENERATE_HEADERS_INCLUDE_PREFIX}")
    list(APPEND FLATBUFFERS_GENERATE_HEADERS_FLAGS 
         "--include-prefix" ${FLATBUFFERS_GENERATE_HEADERS_INCLUDE_PREFIX})
  endif()

  set(generated_custom_commands)

  # Create rules to generate the code for each schema.
  foreach(schema ${FLATBUFFERS_GENERATE_HEADERS_SCHEMAS})
    get_filename_component(filename ${schema} NAME_WE)
    set(generated_include "${generated_include_dir}/${filename}_generated.h")
    # Add the embedded schema header in the output set if requested.
    if("${FLATBUFFERS_GENERATE_HEADERS_FLAGS}" MATCHES "--bfbs-gen-embed")
      list(APPEND generated_include "${generated_include_dir}/${filename}_bfbs_generated.h")
    endif()

    # Generate files for grpc if needed
    set(generated_source_file)
    if("${FLATBUFFERS_GENERATE_HEADERS_FLAGS}" MATCHES "--grpc")
      # Check if schema file contain a rpc_service definition
      file(STRINGS ${schema} has_grpc REGEX "rpc_service")
      if(has_grpc)
        list(APPEND generated_include "${generated_include_dir}/${filename}.grpc.fb.h")
        set(generated_source_file "${generated_include_dir}/${filename}.grpc.fb.cc")
      endif()
    endif()

    add_custom_command(
      OUTPUT ${generated_include} ${generated_source_file}
      COMMAND ${FLATC} ${FLATC_ARGS}
      -o ${generated_include_dir}
      ${include_params}
      -c ${schema}
      ${FLATBUFFERS_GENERATE_HEADERS_FLAGS}
      DEPENDS ${FLATC_TARGET} ${schema}
      WORKING_DIRECTORY "${working_dir}"
      COMMENT "Building ${schema} flatbuffers...")
    list(APPEND all_generated_header_files ${generated_include})
    list(APPEND all_generated_source_files ${generated_source_file})
    list(APPEND generated_custom_commands "${generated_include}" "${generated_source_file}")

    # Generate the binary flatbuffers schemas if instructed to.
    if (NOT ${FLATBUFFERS_GENERATE_HEADERS_BINARY_SCHEMAS_DIR} STREQUAL "")
      set(binary_schema
          "${FLATBUFFERS_GENERATE_HEADERS_BINARY_SCHEMAS_DIR}/${filename}.bfbs")
      add_custom_command(
        OUTPUT ${binary_schema}
        COMMAND ${FLATC} -b --schema
        -o ${FLATBUFFERS_GENERATE_HEADERS_BINARY_SCHEMAS_DIR}
        ${include_params}
        ${schema}
        DEPENDS ${FLATC_TARGET} ${schema}
        WORKING_DIRECTORY "${working_dir}")
      list(APPEND generated_custom_commands "${binary_schema}")
      list(APPEND all_generated_binary_files ${binary_schema})
    endif()
  endforeach()

  # Create an additional target as add_custom_command scope is only within same directory (CMakeFile.txt)
  set(generate_target fuzztest_GENERATE_${FLATBUFFERS_GENERATE_HEADERS_TARGET})
  add_custom_target(${generate_target} ALL
                    DEPENDS ${generated_custom_commands}
                    COMMENT "Generating flatbuffer target fuzztest_${FLATBUFFERS_GENERATE_HEADERS_TARGET}")

  # Set up interface library
  add_library(fuzztest_${FLATBUFFERS_GENERATE_HEADERS_TARGET} INTERFACE)
  add_dependencies(
    fuzztest_${FLATBUFFERS_GENERATE_HEADERS_TARGET}
    ${FLATC}
    ${FLATBUFFERS_GENERATE_HEADERS_SCHEMAS})
  target_include_directories(
    fuzztest_${FLATBUFFERS_GENERATE_HEADERS_TARGET}
    INTERFACE ${generated_target_dir})

  # Organize file layout for IDEs.
  source_group(
    TREE "${generated_target_dir}"
    PREFIX "Flatbuffers/Generated/Headers Files"
    FILES ${all_generated_header_files})
  source_group(
    TREE "${generated_target_dir}"
    PREFIX "Flatbuffers/Generated/Source Files"
    FILES ${all_generated_source_files})
  source_group(
    TREE ${working_dir}
    PREFIX "Flatbuffers/Schemas"
    FILES ${FLATBUFFERS_GENERATE_HEADERS_SCHEMAS})
  if (NOT ${FLATBUFFERS_GENERATE_HEADERS_BINARY_SCHEMAS_DIR} STREQUAL "")
    source_group(
      TREE "${FLATBUFFERS_GENERATE_HEADERS_BINARY_SCHEMAS_DIR}"
      PREFIX "Flatbuffers/Generated/Binary Schemas"
      FILES ${all_generated_binary_files})
  endif()
endfunction()
