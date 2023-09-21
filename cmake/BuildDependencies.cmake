cmake_minimum_required(VERSION 3.19)

include(FetchContent)

set(gtest_URL https://github.com/google/googletest.git)
set(gtest_TAG v1.14.0)

set(absl_URL https://github.com/abseil/abseil-cpp.git)
set(absl_TAG db08109eeb15fcd856761557f1668c2b34690036)

set(re2_URL https://github.com/google/re2.git)
set(re2_TAG 2023-09-01)

set(proto_URL https://github.com/protocolbuffers/protobuf.git)
set(proto_TAG 33b78e67a92c7ba1ecc2e19a037cd2e12f4c5e27)

# From https://www.antlr.org/download.html
set(antlr_cpp_URL https://www.antlr.org/download/antlr4-cpp-runtime-4.12.0-source.zip)
set(antlr_cpp_MD5 acf7371bd7562188712751266d8a7b90)

set(nlohmann_json_URL https://github.com/nlohmann/json.git)
set(nlohmann_json_TAG v3.11.2)

if (FUZZTEST_USE_GTEST OR FUZZTEST_TESTING)
  FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY ${nlohmann_json_URL}
    GIT_TAG        ${nlohmann_json_TAG}
  )
  FetchContent_MakeAvailable(nlohmann_json)

  FetchContent_Declare(
    googletest
    GIT_REPOSITORY ${gtest_URL}
    GIT_TAG        ${gtest_TAG}
  )
endif ()

FetchContent_Declare(
  abseil-cpp
  GIT_REPOSITORY ${absl_URL}
  GIT_TAG        ${absl_TAG}
)

FetchContent_Declare(
  antlr_cpp
  URL      ${antlr_cpp_URL}
  URL_HASH MD5=${antlr_cpp_MD5}
)

FetchContent_Declare(
  re2
  GIT_REPOSITORY ${re2_URL}
  GIT_TAG        ${re2_TAG}
)

if (FUZZTEST_TESTING)
  FetchContent_Declare(
    protobuf
    GIT_REPOSITORY ${proto_URL}
    GIT_TAG        ${proto_TAG}
  )
endif ()

FetchContent_MakeAvailable(antlr_cpp)
set(ABSL_PROPAGATE_CXX_STD ON)
set(ABSL_ENABLE_INSTALL ON)
FetchContent_MakeAvailable(abseil-cpp)
set(RE2_BUILD_TESTING OFF CACHE BOOL "")
FetchContent_MakeAvailable(re2)

if (FUZZTEST_USE_GTEST OR FUZZTEST_TESTING)
  FetchContent_MakeAvailable(googletest)
endif()

if (FUZZTEST_TESTING)
  set(protobuf_BUILD_TESTS OFF)
  set(protobuf_INSTALL OFF)
  FetchContent_MakeAvailable(protobuf)
endif ()
