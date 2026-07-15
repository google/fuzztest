load("//third_party/bazel_rules/rules_rust/rust:defs.bzl", "rust_library", "rust_test")

licenses(["notice"])

rust_test(
    name = "worker_test",
    srcs = ["worker_test.rs"],
    data = [
        "@com_google_fuzztest//rust/e2e_tests/testdata:fuzztest_main",
    ],
    deps = [
        ":test_utils",
        "//third_party/gtest_rust/googletest",
    ],
)

rust_test(
    name = "standalone_mode_test",
    srcs = ["standalone_mode_test.rs"],
    data = [
        "@com_google_fuzztest//centipede/google:centipede_uninstrumented",
        "@com_google_fuzztest//rust/e2e_tests/testdata:fuzztest_main",
        "@com_google_fuzztest//rust/e2e_tests/testdata:standalone_fuzz_tests_bin",
    ],
    deps = [
        ":test_utils",
        "//third_party/gtest_rust/googletest",
    ],
)

rust_test(
    name = "worker_with_centipede_test",
    srcs = ["worker_with_centipede_test.rs"],
    data = [
        "@com_google_fuzztest//centipede/google:centipede_uninstrumented",
        "@com_google_fuzztest//rust/e2e_tests/testdata:fuzztest_main",
    ],
    deps = [
        ":test_utils",
        "//third_party/gtest_rust/googletest",
        "//third_party/rust/rand/v0_10:rand",
    ],
)

rust_test(
    name = "worker_with_centipede_sanitizer_test",
    srcs = ["worker_with_centipede_sanitizer_test.rs"],
    data = [
        "@com_google_fuzztest//centipede/google:centipede_uninstrumented",
        "@com_google_fuzztest//rust/e2e_tests/testdata:fuzztest_main",
    ],
    rustc_flags = ["-Zallow-features=cfg_sanitize"],
    deps = [
        ":test_utils",
        "//third_party/gtest_rust/googletest",
    ],
)

rust_library(
    name = "test_utils",
    testonly = 1,
    srcs = ["test_utils.rs"],
    deps = [
        "//third_party/gtest_rust/googletest",
    ],
)

rust_test(
    name = "gtest_registration_test",
    srcs = ["gtest_registration_test.rs"],
    data = [
        "@com_google_fuzztest//rust/e2e_tests/testdata:fuzz_tests_as_gtests",
    ],
    deps = [
        "//third_party/gtest_rust/googletest",
    ],
)

rust_test(
    name = "replay_test",
    srcs = ["replay_test.rs"],
    data = [
        "@com_google_fuzztest//centipede/google:centipede_uninstrumented",
        "@com_google_fuzztest//rust/e2e_tests/testdata:replay_fuzz_tests_bin",
    ],
    deps = [
        ":test_utils",
        "//third_party/gtest_rust/googletest",
    ],
)
