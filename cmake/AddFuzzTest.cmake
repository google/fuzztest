function(link_fuzztest name)
  target_link_libraries(
    ${name}
    PRIVATE
    fuzztest::fuzztest
    fuzztest::fuzztest_gtest_main
  )
endfunction()

function(link_fuzztest_core name)
  target_link_libraries(
    ${name}
    PRIVATE
    fuzztest::fuzztest_core
    fuzztest::fuzztest_gtest_main
  )
endfunction()
