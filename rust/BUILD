load("//third_party/bazel_rules/rules_rust/rust:defs.bzl", "rust_library", "rust_test")

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
        "//third_party/rust/anyhow/v1:anyhow",
        "//third_party/rust/clap/v4:clap",
        "//third_party/rust/humantime/v2:humantime",
        "//third_party/rust/inventory/v0_3:inventory",
        "//third_party/rust/num_traits/v0_2:num_traits",
        "//third_party/rust/postcard/v1:postcard",
        "//third_party/rust/rand/v0_10:rand",
        "//third_party/rust/serde/v1:serde",
        "//third_party/rust/spin/v0_10:spin",
        "//third_party/rust/tempfile/v3:tempfile",
        "@com_google_fuzztest//rust/coverage",
        "@com_google_fuzztest//rust/engine",
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
        "//third_party/gtest_rust/googletest",
    ],
)
