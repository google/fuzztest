#!/bin/bash

# Copyright 2023 The Centipede Authors.
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
#
# This test ensures that Centipede can handle periodic saved execution
# results. A periodic saved execution result is an execution result that is
# saved to the output buffer after a certain period of time, even if the
# execution has not completed.

set -eu

source "$(dirname "$0")/../test_util.sh"
source "$(dirname "$0")/../test_fuzzing_util.sh"

CENTIPEDE_TEST_SRCDIR="$(fuzztest::internal::get_centipede_test_srcdir)"

fuzztest::internal::maybe_set_var_to_executable_path \
  CENTIPEDE_BINARY "${CENTIPEDE_TEST_SRCDIR}/batch_fuzz_example/customized_centipede"
fuzztest::internal::maybe_set_var_to_executable_path \
  TARGET_BINARY "${CENTIPEDE_TEST_SRCDIR}/batch_fuzz_example/batch_fuzz_target"

# Shorthand for customized_centipede --binary=batch_fuzz_target.
batch_fuzz() {
  set -x
  "${CENTIPEDE_BINARY}" \
    --binary="${TARGET_BINARY}" \
    --symbolizer_path=/dev/null \
    --print_runner_log \
    "$@" 2>&1
  set +x
}

echo -e "\n=== Sanity test\n"
fuzztest::internal::run_some_fuzzing batch_fuzz

echo -e "\n=== Crash test\n"
fuzztest::internal::test_crashing_target batch_fuzz "foo" "fuz" "Catch you"

export CENTIPEDE_RUNNER_FLAGS=":use_pc_features:use_cmp_features"
echo -e "\n=== Fuzz test with CENTIPEDE_RUNNER_FLAGS=${CENTIPEDE_RUNNER_FLAGS}\n"
fuzztest::internal::test_replaying_target \
  batch_fuzz "Ratio of inputs with features: 2/2" "foo" "foo"

export CENTIPEDE_RUNNER_FLAGS=":use_pc_features:use_cmp_features:skip_seen_features:"
echo -e "\n=== Fuzz test with CENTIPEDE_RUNNER_FLAGS=${CENTIPEDE_RUNNER_FLAGS}\n"
fuzztest::internal::test_replaying_target \
  batch_fuzz "Ratio of inputs with features: 1/2" "foo" "foo"

export CENTIPEDE_RUNNER_FLAGS=":rss_limit_mb=1024:"
echo -e "\n=== OOM test with CENTIPEDE_RUNNER_FLAGS=${CENTIPEDE_RUNNER_FLAGS}\n"
fuzztest::internal::test_replaying_target \
  batch_fuzz 'RSS limit exceeded: [0-9][0-9]* > 1024' "oom"

export CENTIPEDE_RUNNER_FLAGS=":timeout_per_input=1:"
echo -e "\n=== Timeout test with CENTIPEDE_RUNNER_FLAGS=${CENTIPEDE_RUNNER_FLAGS}\n"
fuzztest::internal::test_replaying_target \
  batch_fuzz 'Per-input timeout exceeded: [0-9][0-9]* > 1' "slp"

echo "PASS"
