# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_cc//cc:cc_binary.bzl", "cc_binary")
load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_java//java:java_library.bzl", "java_library")
load("@rules_java//java:java_test.bzl", "java_test")

licenses(["notice"])

java_library(
    name = "engine_api",
    srcs = [
        "DiagnosticSink.java",
        "FuzzTestAdapter.java",
        "FuzzTestAdapterManager.java",
    ],
    visibility = [
        "@com_google_fuzztest//java:__subpackages__",
    ],
)

cc_library(
    name = "engine_jni_lib",
    srcs = ["engine_jni.cc"],
    hdrs = ["engine_jni.h"],
    copts = [
        "-fsanitize-coverage=0",
        "-fno-sanitize=address,hwaddress,thread,undefined",
    ],
    deps = [
        "@bazel_tools//tools/jdk:jni",
        "@com_google_fuzztest//centipede:engine_abi",
        "@com_google_fuzztest//centipede:engine_worker",
    ],
    alwayslink = True,
)

cc_binary(
    name = "libfuzztest_java_engine_jni.so",
    linkopts = select({
        "@platforms//os:macos": [
            "-ldl",
            "-lpthread",
            "-Wl,-undefined,dynamic_lookup",
        ],
        "//conditions:default": [
            "-ldl",
            "-lpthread",
            "-lrt",
        ],
    }),
    linkshared = True,
    linkstatic = True,
    deps = [":engine_jni_lib"],
)

java_library(
    name = "engine",
    srcs = ["FuzzTestEngine.java"],
    data = [
        ":libfuzztest_java_engine_jni.so",
        "@com_google_fuzztest//centipede:engine_controller_with_subprocess",
    ],
    visibility = [
        "@com_google_fuzztest//java:__subpackages__",
    ],
    exports = [":engine_api"],
    deps = [
        ":engine_api",  # buildcleaner: keep
    ],
)

cc_binary(
    name = "libfuzztest_java_engine_test_jni.so",
    testonly = True,
    srcs = [
        "engine_jni.h",
        "engine_jni_test_driver.cc",
    ],
    linkopts = ["-ldl"],
    linkshared = True,
    linkstatic = True,
    deps = [
        "@bazel_tools//tools/jdk:jni",
        "@com_google_fuzztest//centipede:engine_abi",
    ],
)
