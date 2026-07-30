load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library", "rust_test")

licenses(["notice"])

rust_library(
    name = "cargo_fuzztest",
    srcs = ["src/lib.rs"],
    edition = "2024",
    visibility = ["@com_google_fuzztest//rust:__subpackages__"],
    deps = [
        "@crate_index//:anyhow",  # v1
        "@crate_index//:clap",  # v4
        "@crate_index//:serde",  # v1
        "@crate_index//:serde_json",  # v1
        "@com_google_fuzztest//rust/options:fuzztest_options",
    ],
)

rust_binary(
    name = "cargo_fuzztest_bin",
    srcs = ["src/main.rs"],
    edition = "2024",
    visibility = ["@com_google_fuzztest//rust:__subpackages__"],
    deps = [
        ":cargo_fuzztest",
        "@crate_index//:anyhow",  # v1
        "@crate_index//:clap",  # v4
        "@com_google_fuzztest//rust/options:fuzztest_options",
    ],
)

rust_test(
    name = "cargo_fuzztest_lib_test",
    args = ["--test-threads=1"],
    crate = ":cargo_fuzztest",
    edition = "2024",
    deps = [
        "@crate_index//:googletest",
    ],
)

rust_test(
    name = "dummy_fuzz_crate_bin",
    srcs = ["test_crates/dummy_fuzz_crate/src/lib.rs"],
    edition = "2024",
    tags = [
        "manual",
        "notap",
    ],
    deps = [
        "@crate_index//:googletest",
        "@com_google_fuzztest//rust:fuzztest",
    ],
)

rust_test(
    name = "runner_test",
    srcs = [
        "tests/common/mod.rs",
        "tests/runner_test.rs",
    ],
    data = [
        ":dummy_fuzz_crate_bin",
    ],
    edition = "2024",
    deps = [
        ":cargo_fuzztest",
        "@crate_index//:googletest",
        "@crate_index//:anyhow",  # v1
        "@com_google_fuzztest//rust/options:fuzztest_options",
    ],
)
