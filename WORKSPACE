# Copyright 2023 Google LLC
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

def http_archive(name, sha256, strip_prefix, urls, build_file=None):
    archive = {
        'name': name,
        'sha256': sha256,
        'strip_prefix': strip_prefix,
        'urls': urls
    }
    if build_file:
        archive['build_file'] = build_file
    return archive

def load_dependencies():
    dependencies = [
        http_archive(
            name = "bazel_skylib",
            sha256 = "f7be3474d42aae265405a592bb7da8e171919d74c16f082a5457840f06054728",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.2.1/bazel-skylib-1.2.1.tar.gz",
                "https://github.com/bazelbuild/bazel-skylib/releases/download/1.2.1/bazel-skylib-1.2.1.tar.gz",
            ],
        ),
        http_archive(
            name = "com_google_absl",
            sha256 = "3ea49a7d97421b88a8c48a0de16c16048e17725c7ec0f1d3ea2683a2a75adc21",
            strip_prefix = "abseil-cpp-20230125.0",
            url = "https://github.com/abseil/abseil-cpp/archive/refs/tags/20230125.0.tar.gz",
        ),
        http_archive(
            name = "com_googlesource_code_re2",
            sha256 = "f89c61410a072e5cbcf8c27e3a778da7d6fd2f2b5b1445cd4f4508bee946ab0f",
            strip_prefix = "re2-2022-06-01",
            url = "https://github.com/google/re2/archive/refs/tags/2022-06-01.tar.gz",
        ),
        http_archive(
            name = "antlr_cpp",
            build_file = "//bazel:antlr_cpp_runtime.BUILD",
            sha256 = "642d59854ddc0cebb5b23b2233ad0a8723eef20e66ef78b5b898d0a67556893b",
            url = "https://www.antlr.org/download/antlr4-cpp-runtime-4.12.0-source.zip",
        ),
    ]
    
    test_dependencies = [
        http_archive(
            name = "com_google_googletest",
            sha256 = "81964fe578e9bd7c94dfdb09c8e4d6e6759e19967e397dbea48d1c10e45d0df2",
            strip_prefix = "googletest-release-1.12.1",
            url = "https://github.com/google/googletest/archive/refs/tags/release-1.12.1.tar.gz",
        ),
        http_archive(
            name = "com_nlohmann_json",
            build_file = "//bazel:nlohmann_json.BUILD",
            sha256 = "d69f9deb6a75e2580465c6c4c5111b89c4dc2fa94e3a85fcd2ffcd9a143d9273",
            strip_prefix = "json-3.11.2",
            url = "https://github.com/nlohmann/json/archive/refs/tags/v3.11.2.tar.gz",
        ),
        http_archive(
            name = "com_google_protobuf",
            sha256 = "4a7e87e4166c358c63342dddcde6312faee06ea9d5bb4e2fa87d3478076f6639",
            strip_prefix = "protobuf-21.5",
            url = "https://github.com/protocolbuffers/protobuf/archive/refs/tags/v21.5.tar.gz"
        ),
        http_archive(
            name = "rules_proto",
            sha256 = "e017528fd1c91c5a33f15493e3a398181a9e821a804eb7ff5acdd1d2d6c2b18d",
            strip_prefix = "rules_proto-4.0.0-3.20.0",
            url = "https://github.com/bazelbuild/rules_proto/archive/refs/tags/4.0.0-3.20.0.tar.gz",
        ),
    ]

    return dependencies, test_dependencies

# Load transitive dependencies
transitive_dependencies, test_transitive_dependencies = load_dependencies()

workspace(name="com_google_fuzztest")

for dependency in transitive_dependencies:
    http_archive(**dependency)

# Direct dependencies
direct_dependencies = [
    http_archive(
        name = "com_google_absl",
        sha256 = "3ea49a7d97421b88a8c48a0de16c16048e17725c7ec0f1d3ea2683a2a75adc21",
        strip_prefix = "abseil-cpp-20230125.0",
        url = "https://github.com/abseil/abseil-cpp/archive/refs/tags/20230125.0.tar.gz",
    ),
    http_archive(
        name = "com_googlesource_code_re2",
        sha256 = "f89c61410a072e5cbcf8c27e3a778da7d6fd2f2b5b1445cd4f4508bee946ab0f",
        strip_prefix = "re2-2022-06-01",
        url = "https://github.com/google/re2/archive/refs/tags/2022-06-01.tar.gz",
    ),
    http_archive(
        name = "antlr_cpp",
        build_file = "//bazel:antlr_cpp_runtime.BUILD",
        sha256 = "642d59854ddc0cebb5b23b2233ad0a8723eef20e66ef78b5b898d0a67556893b",
        url = "https://www.antlr.org/download/antlr4-cpp-runtime-4.12.0-source.zip",
    ),
]

for dependency in direct_dependencies:
    http_archive(**dependency)

# Direct dependencies for running tests
test_dependencies = [
    http_archive(
        name = "com_google_googletest",
        sha256 = "81964fe578e9bd7c94dfdb09c8e4d6e6759e19967e397dbea48d1c10e45d0df2",
        strip_prefix = "googletest-release-1.12.1",
        url = "https://github.com/google/googletest/archive/refs/tags/release-1.12.1.tar.gz",
    ),
    http_archive(
        name = "com_nlohmann_json",
        build_file = "//bazel:nlohmann_json.BUILD",
        sha256 = "d69f9deb6a75e2580465c6c4c5111b89c4dc2fa94e3a85fcd2ffcd9a143d9273",
        strip_prefix = "json-3.11.2",
        url = "https://github.com/nlohmann/json/archive/refs/tags/v3.11.2.tar.gz",
    ),
    http_archive(
        name = "com_google_protobuf",
        sha256 = "4a7e87e4166c358c63342dddcde6312faee06ea9d5bb4e2fa87d3478076f6639",
        strip_prefix = "protobuf-21.5",
        url = "https://github.com/protocolbuffers/protobuf/archive/refs/tags/v21.5.tar.gz"
    ),
    http_archive(
        name = "rules_proto",
        sha256 = "e017528fd1c91c5a33f15493e3a398181a9e821a804eb7ff5acdd1d2d6c2b18d",
        strip_prefix = "rules_proto-4.0.0-3.20.0",
        url = "https://github.com/bazelbuild/rules_proto/archive/refs/tags/4.0.0-3.20.0.tar.gz",
    ),
]

for dependency in test_dependencies:
    http_archive(**dependency)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")
protobuf_deps()

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")
rules_proto_dependencies()
rules_proto_toolchains()
