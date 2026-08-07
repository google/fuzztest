load("@rules_rust//rust:defs.bzl", "rust_clippy", "rust_library")

licenses(["notice"])

rust_library(
    name = "engine",
    srcs = [
        "src/engine_ffi.rs",
        "src/lib.rs",
    ],
    deps = [
        "@com_google_fuzztest//centipede:engine_abi",
        "@com_google_fuzztest//centipede:engine_controller_with_subprocess",
        "@com_google_fuzztest//centipede:engine_worker",
    ],
    edition = "2024",
    visibility = ["@com_google_fuzztest//rust:__subpackages__"],
)

rust_clippy(
    name = "engine_clippy",
    deps = [
        ":engine",
    ],
)
