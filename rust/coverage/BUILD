load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

licenses(["notice"])

rust_library(
    name = "coverage",
    srcs = [
        "src/coverage.rs",
        "src/lib.rs",
    ],
    edition = "2024",
    visibility = ["@com_google_fuzztest//rust:__subpackages__"],
    deps = [
        "@com_google_fuzztest//centipede:sancov_runtime",
    ],
)

rust_test(
    name = "coverage_test",
    # Avoid interference on coverage collection between threads.
    args = ["--test-threads=1"],
    crate = ":coverage",
    edition = "2024",
    env = {
        "CENTIPEDE_RUNNER_FLAGS": ":use_cmp_features:",
    },
    # TODO: b/437896409 - Replace with global config once it's available.
    rustc_flags = [
        "-Cpasses=sancov-module",
        "-Cllvm-args=-sanitizer-coverage-level=1",
        "-Cllvm-args=-sanitizer-coverage-trace-compares",
    ],
    deps = [
        "@crate_index//:googletest",
    ],
)
