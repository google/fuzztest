load("//third_party/bazel_rules/rules_rust/rust:defs.bzl", "rust_library")

licenses(["notice"])

rust_library(
    name = "engine",
    srcs = [
        "src/engine_ffi.rs",
        "src/lib.rs",
    ],
    cc_deps = [
        "@com_google_fuzztest//centipede:engine_abi",
        "@com_google_fuzztest//centipede:engine_controller_with_subprocess",
        "@com_google_fuzztest//centipede:engine_worker",
    ],
    visibility = ["@com_google_fuzztest//rust:__subpackages__"],
)
