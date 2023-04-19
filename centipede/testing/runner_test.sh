#!/bin/bash

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

# This sh_test runs various tests on test_fuzz_target,
# which is linked against :centipede_runner.

set -eu

source "$(dirname "$0")/../test_util.sh"

target="$(centipede::get_centipede_test_srcdir)/testing/test_fuzz_target"
non_pie_target="$(centipede::get_centipede_test_srcdir)/testing/test_fuzz_target_non_pie"

# Create input files.
oom="${TEST_TMPDIR}/oom"
slo="${TEST_TMPDIR}/slo"
f1="${TEST_TMPDIR}/f1"
func1="${TEST_TMPDIR}/func1"
minus1="${TEST_TMPDIR}/minus1"

echo -n oom > "${oom}"  # Triggers OOM
echo -n slo > "${slo}"  # Triggers sleep(10)
echo -n f1 > "${f1}"    # Arbitrary input.
echo -n func1 > "${func1}"  # Triggers a call to SingleEdgeFunc.
echo -n "-1"  > "${minus1}" # Triggers return -1

# Checks that the files with coverage features for f1 and func1
# are correctly generated.
check_features_files_f1_and_f02() {
  echo ======== Check features files.
  # Files should exist and be non-empty.
  [[ -s "${f1}-features" ]] || die "features file not found: f1"
  [[ -s "${func1}-features" ]] || die "features file not found: func1"
  # Files should be different, because inputs have different sizes,
  # and so the coverage features for the loop in test_fuzz_target
  # will be different.
  cmp "${f1}-features" "${func1}-features" && die "features files are the same"
  echo ======== features files are different.
}

export CENTIPEDE_RUNNER_FLAGS=\
":use_pc_features:use_cmp_features:use_dataflow_features:path_level=10:"

echo ======== Check that return -1 generates empty feature file.
"${target}" "${minus1}"
[[ -f "${minus1}-features" ]] || die "features file not found: minus1"
[[ -s "${minus1}-features" ]] && die "features file is not empty, but should be"

# Run two files separately.
# test_fuzz_target prints its input bytes in hex form,
# e.g. for 'f1' it will print '{66, 31}'
rm -fv "${TEST_TMPDIR}"/*-features
echo ======== Run f1
"${target}" "${f1}"   | grep "{66, 31}"
echo ======== Run func1
"${target}" "${func1}"  | grep "{66, 75, 6e, 63, 31}"

echo ======== Trying non-pie target binary
"${non_pie_target}" "${f1}"   | grep "{66, 31}"

check_features_files_f1_and_f02

# Run two files in one process.
rm -fv "${TEST_TMPDIR}"/*-features
echo ======== Run f1 func1
"${target}" "${f1}" "${func1}"
check_features_files_f1_and_f02

# Check OOM. The test target allocates 4Gb, and we make sure
# this can be detected with appropriate limit (address_space_limit_mb),
# and can not be detected with a larger limit.
echo ======== Check OOM behaviour with address_space_limit_mb
CENTIPEDE_RUNNER_FLAGS=":address_space_limit_mb=4096:" $target "${oom}" \
  && die "failed to die on 4G OOM (address_space_limit_mb)"
# must pass.
CENTIPEDE_RUNNER_FLAGS=":address_space_limit_mb=8192:" $target "${oom}"

echo ======== Check OOM behaviour with rss_limit_mb
CENTIPEDE_RUNNER_FLAGS=":rss_limit_mb=4096:" $target "${oom}" \
  && die "failed to die on 4G OOM (rss_limit_mb)"

CENTIPEDE_RUNNER_FLAGS=":rss_limit_mb=8192:" $target "${oom}"  # must pass

echo ======== Check timeout
CENTIPEDE_RUNNER_FLAGS=":timeout_per_input=567:" "${target}" \
  2>&1 | grep "timeout_per_input:.567"

CENTIPEDE_RUNNER_FLAGS=":timeout_per_input=2:" "${target}" "${slo}" \
  2>&1 | grep "Per-input timeout exceeded"

echo "PASS"
