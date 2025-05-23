# Copyright 2025 Google LLC
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

function(_link_libfuzzer_in_compatibility_mode name)
  if (FUZZTEST_COMPATIBILITY_MODE STREQUAL "libfuzzer")
    EXECUTE_PROCESS (
        COMMAND bash -c "find \${PATH//:/ } -maxdepth 1 -executable -name 'llvm-config*'"
        OUTPUT_VARIABLE LLVM_CONFIG OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    EXECUTE_PROCESS(
      COMMAND bash -c "find $(${LLVM_CONFIG} --libdir) \
      -name libclang_rt.fuzzer_no_main-x86_64.a"
      OUTPUT_VARIABLE FUZZER_NO_MAIN OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT FUZZER_NO_MAIN)
      # LLVM_ENABLE_PER_TARGET_RUNTIME_DIR was set to ON when building LLVM.
      EXECUTE_PROCESS(
        COMMAND bash -c "find / -regex \
        \"$(${LLVM_CONFIG} --libdir).*$(${LLVM_CONFIG} --host-target).*libclang_rt.fuzzer_no_main.a\""
        OUTPUT_VARIABLE FUZZER_NO_MAIN OUTPUT_STRIP_TRAILING_WHITESPACE
      )
    endif()
    target_link_libraries(${name} PRIVATE ${FUZZER_NO_MAIN})
  endif ()
endfunction()