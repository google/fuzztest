load("@rules_rust//rust:defs.bzl", "rust_test")

package(default_visibility = ["@com_google_fuzztest//rust/e2e_tests:__subpackages__"])

licenses(["notice"])

rust_test(
    name = "fuzztest_main",
    testonly = 1,
    srcs = [
        "fuzz_tests.rs",
    ],
    edition = "2024",
    # TODO: b/437896409 - Replace with global config once it's available.
    rustc_flags = [
        "-Ccodegen-units=1",
        "-Clink-dead-code",
        "-Cpasses=sancov-module",
        "-Cllvm-args=-sanitizer-coverage-level=1",
        "-Cllvm-args=-sanitizer-coverage-trace-compares",
    ],
    tags = [
        "manual",
        "notap",
    ],
    deps = [
        "@crate_index//:googletest",
        "@crate_index//:anyhow",  # v1
        "@crate_index//:inventory",  # v0_3
        "@crate_index//:rand",  # v0_10
        "@com_google_fuzztest//rust:fuzztest",
    ],
)

rust_test(
    name = "standalone_fuzz_tests_bin",
    testonly = 1,
    srcs = [
        "standalone_fuzz_tests.rs",
    ],
    edition = "2024",
    rustc_flags = [
        "-Ccodegen-units=1",
        "-Clink-dead-code",
        "-Cpasses=sancov-module",
        "-Cllvm-args=-sanitizer-coverage-level=1",
        "-Cllvm-args=-sanitizer-coverage-trace-compares",
    ],
    tags = [
        "manual",
        "notap",
    ],
    deps = [
        "@crate_index//:googletest",
        "@crate_index//:anyhow",  # v1
        "@crate_index//:inventory",  # v0_3
        "@crate_index//:rand",  # v0_10
        "@com_google_fuzztest//rust:fuzztest",
    ],
)

rust_test(
    name = "replay_fuzz_tests_bin",
    testonly = 1,
    srcs = [
        "replay_fuzz_tests.rs",
    ],
    edition = "2024",
    harness = "libtest",
    rustc_flags = [
        "-Ccodegen-units=1",
        "-Clink-dead-code",
        "-Cpasses=sancov-module",
        "-Cllvm-args=-sanitizer-coverage-level=1",
        "-Cllvm-args=-sanitizer-coverage-trace-compares",
    ],
    tags = [
        "manual",
        "notap",
    ],
    deps = [
        "@crate_index//:googletest",
        "@crate_index//:anyhow",  # v1
        "@crate_index//:inventory",  # v0_3
        "@crate_index//:rand",  # v0_10
        "@com_google_fuzztest//rust:fuzztest",
    ],
)

rust_test(
    name = "fuzz_tests_as_gtests",
    srcs = ["fuzz_tests_as_gtests.rs"],
    edition = "2024",
    rustc_flags = ["-Zallow-features=cfg_sanitize"],
    tags = [
        "manual",
        "notap",
    ],
    deps = [
        "@crate_index//:googletest",
        "@crate_index//:anyhow",  # v1
        "@crate_index//:inventory",  # v0_3
        "@crate_index//:postcard",  # v1
        "@crate_index//:rand",  # v0_10
        "@com_google_fuzztest//rust:fuzztest",
    ],
)
