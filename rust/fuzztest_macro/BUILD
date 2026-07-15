load("//third_party/bazel_rules/rules_rust/rust:defs.bzl", "rust_proc_macro", "rust_test")

licenses(["notice"])

rust_proc_macro(
    name = "fuzztest_macro",
    srcs = glob(
        [
            "src/**/*.rs",
        ],
        exclude = ["src/test_main.rs"],
    ),
    edition = "2024",
    visibility = ["@com_google_fuzztest//rust:__subpackages__"],
    deps = [
        "//third_party/rust/convert_case/v0_4:convert_case",
        "//third_party/rust/proc_macro2/v1:proc_macro2",
        "//third_party/rust/proc_macro_crate/v3:proc_macro_crate",
        "//third_party/rust/quote/v1:quote",
        "//third_party/rust/syn/v2:syn",
    ],
)

rust_test(
    name = "fuzztest_macro_test",
    srcs = glob(
        ["src/**/*.rs"],
        exclude = ["src/lib.rs"],
    ),
    crate_root = "src/test_main.rs",
    edition = "2024",
    proc_macro_deps = [":fuzztest_macro"],
    deps = [
        "//third_party/gtest_rust/googletest",
        "//third_party/rust/convert_case/v0_4:convert_case",
        "//third_party/rust/proc_macro2/v1:proc_macro2",
        "//third_party/rust/proc_macro_crate/v3:proc_macro_crate",
        "//third_party/rust/quote/v1:quote",
        "//third_party/rust/syn/v2:syn",
    ],
)
