load("@com_google_fuzztest//centipede/testing:build_defs.bzl", "centipede_fuzz_target")

package(default_visibility = [":__subpackages__"])

licenses(["notice"])

################################################################################
#                               Fuzz targets
################################################################################

centipede_fuzz_target(
    name = "batch_fuzz_target",
    fuzz_target = ":standalone_fuzz_target_main",
)

###############################################################################
#                                  Libraries
################################################################################

cc_library(
    name = "customized_centipede_lib",
    srcs = ["customized_centipede.cc"],
    hdrs = ["customized_centipede.h"],
    deps = [
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/strings",
        "@com_google_fuzztest//centipede:centipede_callbacks",
        "@com_google_fuzztest//centipede:command",
        "@com_google_fuzztest//centipede:environment",
        "@com_google_fuzztest//centipede:feature",
        "@com_google_fuzztest//centipede:runner_result",
        "@com_google_fuzztest//centipede:shared_memory_blob_sequence",
        "@com_google_fuzztest//centipede:util",
        "@com_google_fuzztest//common:defs",
        "@com_google_fuzztest//common:logging",
    ],
)

###############################################################################
#                                  Binaries
################################################################################

# A standalone binary with main() that is worth fuzzing.
cc_binary(
    name = "standalone_fuzz_target_main",
    srcs = ["standalone_fuzz_target_main.cc"],
    linkopts = ["-ldl"],
    linkstatic = False,
    deps = [
        "@abseil-cpp//absl/time",
        "@com_google_fuzztest//centipede:centipede_runner_no_main",  # build-cleaner:keep
    ],
)

cc_binary(
    name = "customized_centipede",
    srcs = ["customized_centipede_main.cc"],
    deps = [
        ":customized_centipede_lib",
        "@abseil-cpp//absl/base:nullability",
        "@com_google_fuzztest//centipede:centipede_callbacks",
        "@com_google_fuzztest//centipede:centipede_interface",
        "@com_google_fuzztest//centipede:config_file",
        "@com_google_fuzztest//centipede:environment_flags",
    ],
)

################################################################################
#                                  Tests
################################################################################

cc_test(
    name = "customized_centipede_test",
    srcs = ["customized_centipede_test.cc"],
    data = [":batch_fuzz_target"],
    deps = [
        ":customized_centipede_lib",
        "@com_google_fuzztest//centipede:centipede_callbacks",
        "@com_google_fuzztest//centipede:environment",
        "@com_google_fuzztest//centipede:runner_result",
        "@com_google_fuzztest//common:defs",
        "@com_google_fuzztest//common:test_util",
        "@googletest//:gtest_main",
    ],
)

sh_test(
    name = "customized_centipede_sh_test",
    srcs = ["customized_centipede_test.sh"],
    data = [
        ":batch_fuzz_target",
        ":customized_centipede",
        "@com_google_fuzztest//centipede:test_fuzzing_util_sh",
        "@com_google_fuzztest//centipede:test_util_sh",
    ],
)
