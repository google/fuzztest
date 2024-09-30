# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

workspace(name = "com_google_fuzztest")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

################################################################################
# Direct dependencies required by core FuzzTest (//fuzztest:fuzztest_core)
################################################################################

http_archive(
    name = "com_google_absl",
    sha256 = "338420448b140f0dfd1a1ea3c3ce71b3bc172071f24f4d9a57d59b45037da440",
    strip_prefix = "abseil-cpp-20240116.0",
    url = "https://github.com/abseil/abseil-cpp/releases/download/20240116.0/abseil-cpp-20240116.0.tar.gz"
)

http_archive(
    name = "platforms",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/platforms/releases/download/0.0.10/platforms-0.0.10.tar.gz",
        "https://github.com/bazelbuild/platforms/releases/download/0.0.10/platforms-0.0.10.tar.gz",
    ],
    sha256 = "218efe8ee736d26a3572663b374a253c012b716d8af0c07e842e82f238a0a7ee",
)

################################################################################
# Transitive dependencies for core FuzzTest
################################################################################

# Required by com_google_absl.
http_archive(
    name = "bazel_skylib",
    sha256 = "cd55a062e763b9349921f0f5db8c3933288dc8ba4f76dd9416aac68acee3cb94",
    urls = ["https://github.com/bazelbuild/bazel-skylib/releases/download/1.5.0/bazel-skylib-1.5.0.tar.gz"],
)

################################################################################
# Direct dependencies required for full FuzzTest (//fuzztest:fuzztest)
################################################################################


http_archive(
    name = "com_googlesource_code_re2",
    sha256 = "cd191a311b84fcf37310e5cd876845b4bf5aee76fdd755008eef3b6478ce07bb",
    strip_prefix = "re2-2024-02-01",
    url = "https://github.com/google/re2/releases/download/2024-02-01/re2-2024-02-01.tar.gz",
)

http_archive(
    name = "antlr_cpp",
    build_file = "//bazel:antlr_cpp_runtime.BUILD",
    sha256 = "642d59854ddc0cebb5b23b2233ad0a8723eef20e66ef78b5b898d0a67556893b",
    url = "https://www.antlr.org/download/antlr4-cpp-runtime-4.12.0-source.zip",
)

http_archive(
    name = "com_google_riegeli",
    sha256 = "f8386e44e16d044c1d7151c0b553bb7075d79583d4fa9e613a4be452599e0795",
    strip_prefix = "riegeli-411cda7f6aa81f8b8591b04cf141b1decdcc928c",
    url = "https://github.com/google/riegeli/archive/411cda7f6aa81f8b8591b04cf141b1decdcc928c.tar.gz",
)

################################################################################
# Transitive dependencies required by Riegeli (and therefore by full FuzzTest)
################################################################################

http_archive(
    name = "highwayhash",
    sha256 = "cf891e024699c82aabce528a024adbe16e529f2b4e57f954455e0bf53efae585",
    strip_prefix = "highwayhash-276dd7b4b6d330e4734b756e97ccfb1b69cc2e12",
    urls = ["https://github.com/google/highwayhash/archive/276dd7b4b6d330e4734b756e97ccfb1b69cc2e12.zip"],  # 2019-02-22
    build_file = "@com_google_riegeli//third_party:highwayhash.BUILD",
)

http_archive(
    name = "org_brotli",
    sha256 = "84a9a68ada813a59db94d83ea10c54155f1d34399baf377842ff3ab9b3b3256e",
    strip_prefix = "brotli-3914999fcc1fda92e750ef9190aa6db9bf7bdb07",
    urls = ["https://github.com/google/brotli/archive/3914999fcc1fda92e750ef9190aa6db9bf7bdb07.zip"],  # 2022-11-17
)

http_archive(
    name = "net_zstd",
    sha256 = "b6c537b53356a3af3ca3e621457751fa9a6ba96daf3aebb3526ae0f610863532",
    strip_prefix = "zstd-1.4.5/lib",
    urls = ["https://github.com/facebook/zstd/archive/v1.4.5.zip"],  # 2020-05-22
    build_file = "@com_google_riegeli//third_party:net_zstd.BUILD",
)

http_archive(
    name = "snappy",
    sha256 = "38b4aabf88eb480131ed45bfb89c19ca3e2a62daeb081bdf001cfb17ec4cd303",
    strip_prefix = "snappy-1.1.8",
    urls = ["https://github.com/google/snappy/archive/1.1.8.zip"],  # 2020-01-14
    build_file = "@com_google_riegeli//third_party:snappy.BUILD",
)

################################################################################
# Direct dependencies that are only required for running tests
################################################################################

http_archive(
    name = "com_google_googletest",
    sha256 = "8ad598c73ad796e0d8280b082cebd82a630d73e73cd3c70057938a6501bba5d7",
    strip_prefix = "googletest-1.14.0",
    url = "https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz",
)

http_archive(
    name = "com_nlohmann_json",
    build_file = "//bazel:nlohmann_json.BUILD",
    sha256 = "d69f9deb6a75e2580465c6c4c5111b89c4dc2fa94e3a85fcd2ffcd9a143d9273",
    strip_prefix = "json-3.11.2",
    url = "https://github.com/nlohmann/json/archive/refs/tags/v3.11.2.tar.gz",
)

http_archive(
    name = "com_google_protobuf",
    integrity = "sha256-sjQKpH+vfvEKAygZAxnT877hsk9CbUzo9CU7byfOFts=",
    strip_prefix = "protobuf-28.2",
    url = "https://github.com/protocolbuffers/protobuf/releases/download/v28.2/protobuf-28.2.tar.gz"
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

http_archive(
    name = "rules_proto",
    sha256 = "dc3fb206a2cb3441b485eb1e423165b231235a1ea9b031b4433cf7bc1fa460dd",
    strip_prefix = "rules_proto-5.3.0-21.7",
    url = "https://github.com/bazelbuild/rules_proto/archive/refs/tags/5.3.0-21.7.tar.gz",
)

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")

rules_proto_dependencies()
rules_proto_toolchains()
