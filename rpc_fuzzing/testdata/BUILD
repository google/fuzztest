load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")

package(default_visibility = [
    "@com_google_fuzztest//e2e_tests/testdata:__pkg__",
    "@com_google_fuzztest//fuzztest:__subpackages__",
    "@com_google_fuzztest//rpc_fuzzing:__pkg__",
])

proto_library(
    name = "mini_blogger",
    srcs = ["mini_blogger.proto"],
    target_compatible_with = select({
        "@com_google_fuzztest//rpc_fuzzing:rpc_fuzzing_is_enabled": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
)

cc_proto_library(
    name = "mini_blogger_cc_proto",
    deps = [":mini_blogger"],
)

cc_grpc_library(
    name = "mini_blogger_cc_grpc_proto",
    srcs = [":mini_blogger"],
    grpc_only = True,
    deps = [":mini_blogger_cc_proto"],
)

cc_library(
    name = "mini_blogger_grpc_service",
    srcs = ["grpc/mini_blogger_service.cc"],
    hdrs = ["grpc/mini_blogger_service.h"],
    deps = [
        ":mini_blogger_cc_grpc_proto",
        ":mini_blogger_cc_proto",
        ":mini_blogger_context",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

cc_library(
    name = "mini_blogger_context",
    srcs = ["mini_blogger_context.cc"],
    hdrs = ["mini_blogger_context.h"],
    deps = [
        ":mini_blogger_cc_proto",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
    ],
)
