#!/usr/bin/env python3
#
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
    "@com_google_absl//absl/algorithm:container": "absl::algorithm_container",
    "@com_google_absl//absl/base:core_headers": "absl::core_headers",
    "@com_google_absl//absl/container:flat_hash_map": "absl::flat_hash_map",
    "@com_google_absl//absl/container:flat_hash_set": "absl::flat_hash_set",
    "@com_google_absl//absl/debugging:symbolize": "absl::symbolize",
    "@com_google_absl//absl/flags:flag": "absl::flags",
    "@com_google_absl//absl/flags:parse": "absl::flags_parse",
    "@com_google_absl//absl/functional:any_invocable": "absl::any_invocable",
    "@com_google_absl//absl/functional:function_ref": "absl::function_ref",
    "@com_google_absl//absl/hash:hash": "absl::hash",
    "@com_google_absl//absl/log:check": "absl::log",
    "@com_google_absl//absl/memory:memory": "absl::memory",
    "@com_google_absl//absl/numeric:bits": "absl::bits",
    "@com_google_absl//absl/numeric:int128": "absl::int128",
    "@com_google_absl//absl/random:bit_gen_ref": "absl::random_bit_gen_ref",
    "@com_google_absl//absl/random:distributions": "absl::random_distributions",
    "@com_google_absl//absl/random:random": "absl::random_random",
    "@com_google_absl//absl/status:status": "absl::status",
    "@com_google_absl//absl/strings:cord": "absl::cord",
    "@com_google_absl//absl/strings:str_format": "absl::str_format",
    "@com_google_absl//absl/strings:string_view": "absl::string_view",
    "@com_google_absl//absl/strings:strings": "absl::strings",
    "@com_google_absl//absl/synchronization:synchronization": "absl::synchronization",
    "@com_google_absl//absl/time:time": "absl::time",
    "@com_google_absl//absl/types:optional": "absl::optional",
    "@com_google_absl//absl/types:span": "absl::span",
    "@com_google_absl//absl/types:variant": "absl::variant",
    "@com_google_googletest//:gtest": "GTest::gtest",
    "@com_google_googletest//:gtest_main": "GTest::gmock_main",
    "@com_google_protobuf//:protobuf": "protobuf::libprotobuf",
    "@com_googlesource_code_re2//:re2": "re2::re2",
    "@com_nlohmann_json//:json": "nlohmann_json",
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
