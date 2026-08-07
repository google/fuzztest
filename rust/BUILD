load("@rules_rust//rust:defs.bzl", "rust_clippy", "rust_library", "rust_test")

licenses(["notice"])

exports_files(["BUILD"])

rust_library(
    name = "fuzztest",
    srcs = glob([
        "src/**/*.rs",
    ]),
    edition = "2024",
    proc_macro_deps = [
        "@com_google_fuzztest//rust/fuzztest_macro:fuzztest_macro",
    ],
    rustc_flags = ["-Zallow-features=cfg_sanitize"],
    visibility = ["__subpackages__"],
    deps = [
        "@crate_index//:anyhow",  # v1
        "@crate_index//:clap",  # v4
        "@crate_index//:humantime",  # v2
        "@crate_index//:inventory",  # v0_3
        "@crate_index//:num-traits",
        "@crate_index//:postcard",  # v1
        "@crate_index//:rand",  # v0_10
        "@crate_index//:serde",  # v1
        "@crate_index//:spin",  # v0_10
        "@crate_index//:tempfile",  # v3
        "@com_google_fuzztest//rust/coverage",
        "@com_google_fuzztest//rust/engine",
        "@com_google_fuzztest//rust/options:fuzztest_options",
    ],
)

rust_test(
    name = "fuzztest_test",
    # Avoid interference when setting/resetting environment variables in tests.
    args = ["--test-threads=1"],
    crate = ":fuzztest",
    edition = "2024",
    rustc_flags = ["-Zallow-features=cfg_sanitize"],
    deps = [
        "@crate_index//:googletest",
    ],
)

rust_clippy(
    name = "fuzztest_clippy",
    deps = [
        ":fuzztest",
    ],
)
