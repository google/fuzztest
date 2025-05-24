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

macro(fuzztest_setup_fuzzing_flags)
  if (FUZZTEST_FUZZING_MODE OR (FUZZTEST_COMPATIBILITY_MODE STREQUAL "libfuzzer"))
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -UNDEBUG -fsanitize=address")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -UNDEBUG -fsanitize=address")
    SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
  endif ()
  if (FUZZTEST_COMPATIBILITY_MODE STREQUAL "libfuzzer")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=fuzzer-no-link -DFUZZTEST_COMPATIBILITY_MODE")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=fuzzer-no-link -DFUZZTEST_COMPATIBILITY_MODE")
  endif ()
  if (FUZZTEST_FUZZING_MODE OR (FUZZTEST_COMPATIBILITY_MODE STREQUAL "libfuzzer"))
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize-coverage=inline-8bit-counters -fsanitize-coverage=trace-cmp -fsanitize=address -DADDRESS_SANITIZER")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize-coverage=inline-8bit-counters -fsanitize-coverage=trace-cmp -fsanitize=address -DADDRESS_SANITIZER")
  endif ()
endmacro ()
