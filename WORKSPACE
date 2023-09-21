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
# Transitive dependencies (not directly required by FuzzTest itself)
################################################################################

# Required by com_google_absl.
http_archive(
    name = "bazel_skylib",
    sha256 = "66ffd9315665bfaafc96b52278f57c7e2dd09f5ede279ea6d39b2be471e7e3aa",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.4.2/bazel-skylib-1.4.2.tar.gz",
        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.4.2/bazel-skylib-1.4.2.tar.gz",
    ],
)

################################################################################
# Direct dependencies
################################################################################

http_archive(
    name = "com_google_absl",
    sha256 = "f17ba8d569af3ebf649cbce80d089fed35e046a44f40e0714b6bd6fe83d82738",
    strip_prefix = "abseil-cpp-db08109eeb15fcd856761557f1668c2b34690036",
    url = "https://github.com/abseil/abseil-cpp/archive/db08109eeb15fcd856761557f1668c2b34690036.tar.gz",
)

http_archive(
    name = "com_googlesource_code_re2",
    sha256 = "5bb6875ae1cd1e9fedde98018c346db7260655f86fdb8837e3075103acd3649b",
    strip_prefix = "re2-2023-09-01",
    url = "https://github.com/google/re2/archive/refs/tags/2023-09-01.tar.gz",
)

http_archive(
    name = "antlr_cpp",
    build_file = "//bazel:antlr_cpp_runtime.BUILD",
    sha256 = "642d59854ddc0cebb5b23b2233ad0a8723eef20e66ef78b5b898d0a67556893b",
    url = "https://www.antlr.org/download/antlr4-cpp-runtime-4.12.0-source.zip",
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
    sha256 = "6f1f962933da7728d81e0467b7ee6f99987c02fc284ff929eb99aeb375ee4b90",
    strip_prefix = "protobuf-33b78e67a92c7ba1ecc2e19a037cd2e12f4c5e27",
    url = "https://github.com/protocolbuffers/protobuf/archive/33b78e67a92c7ba1ecc2e19a037cd2e12f4c5e27.tar.gz"
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
