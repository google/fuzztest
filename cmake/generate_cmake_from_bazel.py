#!/usr/bin/env python3

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

# Experimental script that generates CMakeLists.txt files from BUILD files.
#
# Requires: python3, jinja2, and bazel.
#
# Install jinja2 with `sudo apt install python3-jinja2` or `pip install Jinja2`.
#
# Usage:
#
#   ./generate_cmake_from_bazel.py

import jinja2
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

DIRECTORIES_TO_PROCESS = [
    # TODO(lszekeres): List all.
    "fuzztest",
    "fuzztest/grammars",
    "domain_tests",
]

TRANSLATE_NAME = {
    "//centipede:centipede_runner_no_main": "TODO",
    "@abseil-cpp//absl/algorithm:container": "absl::algorithm_container",
    "@abseil-cpp//absl/base:core_headers": "absl::core_headers",
    "@abseil-cpp//absl/container:flat_hash_map": "absl::flat_hash_map",
    "@abseil-cpp//absl/container:flat_hash_set": "absl::flat_hash_set",
    "@abseil-cpp//absl/debugging:symbolize": "absl::symbolize",
    "@abseil-cpp//absl/flags:flag": "absl::flags",
    "@abseil-cpp//absl/flags:parse": "absl::flags_parse",
    "@abseil-cpp//absl/functional:any_invocable": "absl::any_invocable",
    "@abseil-cpp//absl/functional:function_ref": "absl::function_ref",
    "@abseil-cpp//absl/hash:hash": "absl::hash",
    "@abseil-cpp//absl/log:check": "absl::log",
    "@abseil-cpp//absl/memory:memory": "absl::memory",
    "@abseil-cpp//absl/numeric:bits": "absl::bits",
    "@abseil-cpp//absl/numeric:int128": "absl::int128",
    "@abseil-cpp//absl/random:bit_gen_ref": "absl::random_bit_gen_ref",
    "@abseil-cpp//absl/random:distributions": "absl::random_distributions",
    "@abseil-cpp//absl/random:random": "absl::random_random",
    "@abseil-cpp//absl/status:status": "absl::status",
    "@abseil-cpp//absl/strings:cord": "absl::cord",
    "@abseil-cpp//absl/strings:str_format": "absl::str_format",
    "@abseil-cpp//absl/strings:string_view": "absl::string_view",
    "@abseil-cpp//absl/strings:strings": "absl::strings",
    "@abseil-cpp//absl/synchronization:synchronization": "absl::synchronization",
    "@abseil-cpp//absl/time:time": "absl::time",
    "@abseil-cpp//absl/types:optional": "absl::optional",
    "@abseil-cpp//absl/types:span": "absl::span",
    "@abseil-cpp//absl/types:variant": "absl::variant",
    "@googletest//:gtest": "GTest::gtest",
    "@googletest//:gtest_main": "GTest::gmock_main",
    "@protobuf//:protobuf": "protobuf::libprotobuf",
    "@re2//:re2": "re2::re2",
    "@nlohmann_json//:json": "nlohmann_json",
}


# Returns fuzztest package if label belongs to fuzztest.
def get_fuzztest_package(label):
    for directory in DIRECTORIES_TO_PROCESS:
        package = '//' + directory + ':'
        if label.startswith(package):
            return package
    return None


def get_query_xml(directory):
    command = ["bazel", "query", "--output=xml", ":all"]
    output = subprocess.check_output(command, cwd=directory, stderr=subprocess.PIPE)
    return output


def parse_xml(package, query_xml):
    targets = []
    xml_root = ET.fromstring(query_xml)
    for xml_target in xml_root.findall(".//rule"):
        target = {}
        target["name"] = xml_target.get("name").removeprefix(package)
        target["type"] = xml_target.get("class")
        # TODO(lszekeres): Support fuztest_cc_binary, fuzztest_proto_library,
        # fuzztest_cc_proto_library, etc.
        if target["type"] not in ["cc_library", "cc_test"]:
            continue
        for attribute in ["deps", "hdrs", "srcs"]:
            xml_list = xml_target.find('.//list[@name="' + attribute + '"]')
            if xml_list:
                target[attribute] = []
                for xml_label in xml_list.findall(".//label"):
                    label = xml_label.get("value")
                    if attribute == "deps":
                        fuzztest_package = get_fuzztest_package(label)
                        if fuzztest_package:
                            label = label.removeprefix(fuzztest_package)
                            label = "fuzztest::" + label
                        else:  # non-fuzztest dependency
                            label = TRANSLATE_NAME[label]
                    else:  # hdrs or srcs
                        label = label.removeprefix(package)
                    target[attribute].append(label)
        targets.append(target)
    return targets


def render(template_path, targets):
    with open(template_path, "r") as template_file:
        template = jinja2.Template(template_file.read())
        rendered_template = template.render(targets=targets)
        print(rendered_template)


if __name__ == "__main__":
    script_path = os.path.abspath(__file__)
    script_dir_path = os.path.dirname(script_path)
    repo_path = os.path.dirname(script_dir_path)

    for directory in DIRECTORIES_TO_PROCESS:
        absolute_dir = os.path.join(repo_path, directory)
        relative_dir = os.path.relpath(absolute_dir, repo_path)
        package = '//' + relative_dir + ':'

        print("\n###################################################")
        print(package)
        print("###################################################")

        query_xml = get_query_xml(absolute_dir)
        targets = parse_xml(package, query_xml)

        # TODO(lszekeres): Directly update CMakeLists.txt files.
        template_path = os.path.join(script_dir_path, "CMakeLists.txt.jinja")
        render(template_path, targets)
