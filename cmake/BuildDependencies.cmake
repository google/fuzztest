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

cmake_minimum_required(VERSION 3.19)

include(FetchContent)

set(absl_URL https://github.com/abseil/abseil-cpp.git)
set(absl_TAG d04b964d82ed5146f7e5e34701a5ba69f9514c9a)

set(re2_URL https://github.com/google/re2.git)
set(re2_TAG 2024-07-02)

set(gtest_URL https://github.com/google/googletest.git)
set(gtest_TAG v1.16.0)

# From https://www.antlr.org/download.html
set(antlr_cpp_URL https://www.antlr.org/download/antlr4-cpp-runtime-4.12.0-source.zip)
set(antlr_cpp_MD5 acf7371bd7562188712751266d8a7b90)

set(proto_URL https://github.com/protocolbuffers/protobuf.git)
set(proto_TAG v30.2)

set(nlohmann_json_URL https://github.com/nlohmann/json.git)
set(nlohmann_json_TAG v3.11.3)

set(flatbuffers_URL https://github.com/google/flatbuffers.git)
set(flatbuffers_TAG v25.2.10)

if(POLICY CMP0135)
	cmake_policy(SET CMP0135 NEW)
	set(CMAKE_POLICY_DEFAULT_CMP0135 NEW)
endif()

if(FUZZTEST_DOWNLOAD_DEPENDENCIES OR FUZZTEST_DOWNLOAD_ABSL)
  FetchContent_Declare(
    abseil-cpp
    GIT_REPOSITORY ${absl_URL}
    GIT_TAG        ${absl_TAG}
  )
else()
  find_package(absl REQUIRED)
endif()

if(FUZZTEST_DOWNLOAD_DEPENDENCIES OR FUZZTEST_DOWNLOAD_RE2)
  FetchContent_Declare(
    re2
    GIT_REPOSITORY ${re2_URL}
    GIT_TAG        ${re2_TAG}
  )
else()
  find_package(re2 REQUIRED)
endif()

if(FUZZTEST_DOWNLOAD_DEPENDENCIES OR FUZZTEST_DOWNLOAD_GTEST)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY ${gtest_URL}
    GIT_TAG        ${gtest_TAG}
  )
else()
  find_package(GTest REQUIRED)
endif()

FetchContent_Declare(
  antlr_cpp
  URL          ${antlr_cpp_URL}
  URL_HASH MD5=${antlr_cpp_MD5}
)

if (FUZZTEST_BUILD_FLATBUFFERS)
  if(FUZZTEST_DOWNLOAD_DEPENDENCIES OR FUZZTEST_DOWNLOAD_FLATBUFFERS)
    FetchContent_Declare(
      flatbuffers
      GIT_REPOSITORY ${flatbuffers_URL}
      GIT_TAG        ${flatbuffers_TAG}
    )
  else()
    find_package(flatbuffers REQUIRED)
  endif()
endif()

if (FUZZTEST_BUILD_TESTING)
  if(FUZZTEST_DOWNLOAD_DEPENDENCIES OR FUZZTEST_DOWNLOAD_PROTOBUF)
    FetchContent_Declare(
      protobuf
      GIT_REPOSITORY ${proto_URL}
      GIT_TAG        ${proto_TAG}
    )
    else()
      find_package(Protobuf REQUIRED)
      if(TARGET Protobuf::protobuf AND NOT TARGET protobuf::libprotobuf)
        add_library(protobuf::libprotobuf ALIAS Protobuf::protobuf)
      endif()
  endif ()

  if(FUZZTEST_DOWNLOAD_DEPENDENCIES OR FUZZTEST_DOWNLOAD_NLOHMANN)
    FetchContent_Declare(
      nlohmann_json
      GIT_REPOSITORY ${nlohmann_json_URL}
      GIT_TAG        ${nlohmann_json_TAG}
    )
  else()
    find_package(nlohmann_json REQUIRED)
  endif()
endif ()

if(FUZZTEST_DOWNLOAD_DEPENDENCIES)
  set(ABSL_PROPAGATE_CXX_STD ON)
  set(ABSL_ENABLE_INSTALL ON)
  FetchContent_MakeAvailable(abseil-cpp)
endif()

if(FUZZTEST_DOWNLOAD_DEPENDENCIES OR FUZZTEST_DOWNLOAD_RE2)
  set(RE2_BUILD_TESTING OFF)
  FetchContent_MakeAvailable(re2)
endif ()

if(FUZZTEST_DOWNLOAD_DEPENDENCIES OR FUZZTEST_DOWNLOAD_ABSL)
  set(GTEST_HAS_ABSL ON)
  FetchContent_MakeAvailable(googletest)
endif()

FetchContent_MakeAvailable(antlr_cpp)

if (FUZZTEST_BUILD_TESTING)
  if(FUZZTEST_DOWNLOAD_DEPENDENCIES OR FUZZTEST_DOWNLOAD_PROTOBUF)
    set(protobuf_BUILD_TESTS OFF)
    set(protobuf_INSTALL OFF)
    FetchContent_MakeAvailable(protobuf)
  endif()

  if(FUZZTEST_DOWNLOAD_DEPENDENCIES OR FUZZTEST_DOWNLOAD_NLOHMANN)
    FetchContent_MakeAvailable(nlohmann_json)
  endif()
endif ()

if (FUZZTEST_BUILD_FLATBUFFERS)
  if(FUZZTEST_DOWNLOAD_DEPENDENCIES OR FUZZTEST_DOWNLOAD_FLATBUFFERS)
    set(FLATBUFFERS_BUILD_TESTS OFF)
    set(FLATBUFFERS_BUILD_INSTALL OFF)
    FetchContent_MakeAvailable(flatbuffers)
  endif()
endif()
