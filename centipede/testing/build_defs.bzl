# Copyright 2022 The Centipede Authors.
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

"""This module contains rules that build a fuzz target with sanitizer coverage.
https://clang.llvm.org/docs/SanitizerCoverage.html
To instrument a target with sancov, we apply a bazel transition
https://bazel.build/rules/lib/transition
to change its configuration (i.e., add the necessary compilation flags). The configuration will
affect all its transitive dependencies as well.
"""

# Change the flags from the default ones to sancov:
# https://clang.llvm.org/docs/SanitizerCoverage.html.
def _sancov_transition_impl(settings, attr):
    features_to_strip = ["asan", "tsan", "msan"]
    filtered_features = [
        x
        for x in settings["//command_line_option:features"]
        if x not in features_to_strip
    ]

    # some of the valid sancov flag combinations:
    # trace-pc-guard,pc-table
    # trace-pc-guard,pc-table,trace-cmp
    # trace-pc-guard,pc-table,trace-loads
    sancov = "-fsanitize-coverage=" + attr.sancov

    return {
        # Do not apply clang coverage to the targets as it would interfere with
        # sancov and break test expectations.
        "//command_line_option:collect_code_coverage": False,
        "//command_line_option:copt": settings["//command_line_option:copt"] + [
            "-O2",
            "-fno-builtin",  # prevent memcmp & co from inlining.
            sancov,
            "-gline-tables-only",  # debug info, for coverage reporting tools.
            # https://llvm.org/docs/LibFuzzer.html#fuzzer-friendly-build-mode
            "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
        ],
        "//command_line_option:compilation_mode": "opt",
        "//command_line_option:strip": "never",  # preserve debug info.
        "//command_line_option:features": filtered_features,
        "//command_line_option:compiler": None,
        "//command_line_option:dynamic_mode": "off",
    }

sancov_transition = transition(
    implementation = _sancov_transition_impl,
    inputs = [
        "//command_line_option:copt",
        "//command_line_option:features",
    ],
    outputs = [
        "//command_line_option:collect_code_coverage",
        "//command_line_option:copt",
        "//command_line_option:compilation_mode",
        "//command_line_option:strip",
        "//command_line_option:features",
        "//command_line_option:compiler",
        "//command_line_option:dynamic_mode",
    ],
)

def __sancov_fuzz_target_impl(ctx):
    # We need to copy the executable because starlark doesn't allow
    # providing an executable not created by the rule
    executable_src = ctx.executable.fuzz_target
    executable_dst = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.run_shell(
        inputs = [executable_src],
        outputs = [executable_dst],
        command = "cp %s %s" % (executable_src.path, executable_dst.path),
    )

    # We need to explicitly collect the runfiles from all relevant attributes.
    # See https://docs.bazel.build/versions/main/skylark/rules.html#runfiles
    runfiles = ctx.runfiles()

    # The transition transforms scalar attributes into lists,
    # so we need to index into the list first.
    fuzz_target = ctx.attr.fuzz_target[0]
    runfiles = runfiles.merge(fuzz_target[DefaultInfo].default_runfiles)
    return [DefaultInfo(runfiles = runfiles, executable = executable_dst)]

# Wrapper to build a fuzz target with sanitizer coverage.
# By default it uses some pre-defined set of sancov instrumentations.
# It can be overridden with more advanced ones, see _sancov_transition_impl.
__sancov_fuzz_target = rule(
    implementation = __sancov_fuzz_target_impl,
    attrs = {
        "fuzz_target": attr.label(
            cfg = sancov_transition,
            executable = True,
            mandatory = True,
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
        "sancov": attr.string(),
    },
    executable = True,
)

def centipede_fuzz_target(
        name,
        fuzz_target = None,
        srcs = None,
        # TODO(ussuri): edit --config=centipede too.
        sancov = "trace-pc-guard,pc-table,trace-loads,trace-cmp",
        copts = [],
        linkopts = [],
        deps = []):
    """Generates a fuzz target target instrumented with sancov.

    Args:
      name: A unique name for this target
      srcs: Test source(s); the default is [`name` + ".cc"]; mutually exclusive
          with `fuzz_target`
      fuzz_target: A fuzz target to wrap into sancov; by default, a new target
          named "_" + `name`, compiled from provided or default `srcs`, will be
          created
      sancov: The sancov instrumentations to use, eg. "trace-pc-guard,pc-table";
          see https://clang.llvm.org/docs/SanitizerCoverage.html%29-instrumented
      copts: extra compiler flags
      linkopts: extra linker flags
      deps: Dependency for srcs
    """

    if not fuzz_target:
        # Our own intermediate fuzz target rule.
        fuzz_target = "_" + name

        # A dummy binary that is going to be wrapped by sancov.
        # __sancov_fuzz_target() below uses the dependencies here
        # to rebuild an instrumented binary using transition.
        native.cc_binary(
            name = fuzz_target,
            srcs = srcs or [name + ".cc"],
            deps = deps + ["@com_google_fuzztest//centipede:centipede_runner"],
            copts = copts,
            linkopts = linkopts + [
                "-ldl",
                "-lrt",
                "-lpthread"
            ],
            testonly = True,
        )

    elif srcs:
        fail("`srcs` are mutually exclusive with `fuzz_target`")

    # Bazel transition to build with the right sancov flags.
    __sancov_fuzz_target(
        name = name,
        fuzz_target = fuzz_target,
        sancov = sancov,
        testonly = True,
    )
