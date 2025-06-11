# Fuzz test example for the XML domain.

# NOTE: This BUILD file uses cc_test instead of cc_fuzz_test due to difficulties
# in locating the correct Bazel macro for cc_fuzz_test in this environment.
# For full fuzzing capabilities, ensure your FuzzTest Bazel setup is correct
# and cc_fuzz_test is properly loaded and used.
# See comments in xml_fuzz_test.cc for more details.

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

cc_test(
    name = "xml_fuzz_test",
    srcs = ["xml_fuzz_test.cc"],
    deps = [
        "//fuzztest:fuzztest",  # Main FuzzTest library (provides FUZZ_TEST macro definitions)
        "//fuzztest:fuzztest_gtest_main", # Provides a main function that runs Google Tests and Fuzz Tests
        "//fuzztest/internal/domains:xml_domain_impl", # Our new XML domain library
        "@com_google_googletest//:gtest", # GoogleTest library itself
    ],
)
