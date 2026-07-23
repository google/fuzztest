load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

licenses(["notice"])

exports_files(["BUILD"])

rust_library(
    name = "fuzztest_options",
    srcs = glob([
        "src/**/*.rs",
    ]),
    edition = "2024",
    visibility = ["@com_google_fuzztest//rust:__subpackages__"],
    deps = [
        "@crate_index//:clap",  # v4
        "@crate_index//:humantime",  # v2
    ],
)

rust_test(
    name = "fuzztest_options_test",
    # Avoid interference when setting/resetting environment variables in tests.
    args = ["--test-threads=1"],
    crate = ":fuzztest_options",
    edition = "2024",
    deps = [
        "@crate_index//:googletest",
    ],
)
