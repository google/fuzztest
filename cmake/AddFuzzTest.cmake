function(_link_fuzztest_compatibility_mode name)
  if (FUZZTEST_COMPATIBILITY_MODE STREQUAL "libfuzzer")
    EXECUTE_PROCESS (
        COMMAND bash -c "command -v llvm-config || command -v llvm-config-16 || command -v llvm-config-15 || command -v llvm-config-14 || command -v llvm-config-13 || command -v llvm-config-12 || echo"
        OUTPUT_VARIABLE LLVM_CONFIG OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    EXECUTE_PROCESS(
      COMMAND bash -c "find $(${LLVM_CONFIG} --libdir) -name libclang_rt.fuzzer_no_main-x86_64.a -o -name libclang_rt.fuzzer_no_main.a | head -1"
      OUTPUT_VARIABLE FUZZER_NO_MAIN OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    target_link_libraries(${name} PRIVATE -Wl,-whole-archive ${FUZZER_NO_MAIN} -Wl,-no-whole-archive)
  endif ()
endfunction()

function(link_fuzztest name)
  target_link_libraries(
    ${name}
    PRIVATE
    fuzztest::fuzztest
    fuzztest::fuzztest_gtest_main
  )
  _link_fuzztest_compatibility_mode(${name})
endfunction()

function(link_fuzztest_core name)
  target_link_libraries(
    ${name}
    PRIVATE
    fuzztest::fuzztest_core
    fuzztest::fuzztest_gtest_main
  )
  _link_fuzztest_compatibility_mode(${name})
endfunction()
