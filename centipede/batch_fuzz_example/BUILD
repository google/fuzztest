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
#                                  Binaries
################################################################################

# A standalone binary with main() that is worth fuzzing.
cc_binary(
    name = "standalone_fuzz_target_main",
    srcs = ["standalone_fuzz_target_main.cc"],
    linkopts = ["-ldl"],
    linkstatic = False,
    deps = [
        "@com_google_fuzztest//centipede:centipede_runner_no_main",  # build-cleaner:keep
    ],
)
