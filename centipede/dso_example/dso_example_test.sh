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

# Tests fuzzing of an uninstrumented main binary with instrumented DSO.

set -eu

source "$(dirname "$0")/../test_util.sh"

CENTIPEDE_TEST_SRCDIR="$(fuzztest::internal::get_centipede_test_srcdir)"

fuzztest::internal::maybe_set_var_to_executable_path \
  CENTIPEDE_BINARY "${CENTIPEDE_TEST_SRCDIR}/centipede"

fuzztest::internal::maybe_set_var_to_executable_path \
  CENTIPEDE_RUNNER_NO_MAIN_SO \
  "${CENTIPEDE_TEST_SRCDIR}/centipede_runner_no_main.so"

fuzztest::internal::maybe_set_var_to_executable_path \
  TARGET_BINARY "${CENTIPEDE_TEST_SRCDIR}/dso_example/main"

fuzztest::internal::maybe_set_var_to_executable_path \
  TARGET_BINARY_DLOPEN \
  "${CENTIPEDE_TEST_SRCDIR}/dso_example/main_with_dlopen"

fuzztest::internal::maybe_set_var_to_executable_path \
  TARGET_DSO "${CENTIPEDE_TEST_SRCDIR}/dso_example/fuzz_me.so"

fuzztest::internal::maybe_set_var_to_executable_path \
  OBJDUMP "$(fuzztest::internal::get_objdump_path)"

echo "Running the dso_example binary with dl_path_suffix; expecting it to pass"
CENTIPEDE_RUNNER_FLAGS=":dl_path_suffix=/fuzz_me.so:" "${TARGET_BINARY}"

echo "Running fuzzing for some number of iterations: ${TARGET_BINARY}"
WD="${TEST_TMPDIR}/WD"
LOG="${TEST_TMPDIR}/log2"
fuzztest::internal::ensure_empty_dir "${WD}"
"${CENTIPEDE_BINARY}" --workdir "${WD}" --binary "${TARGET_BINARY} @@" \
  --runner_dl_path_suffix "/fuzz_me.so" --coverage_binary "${TARGET_DSO}" \
  --objdump_path="${OBJDUMP}" \
  --num_runs=100  2>&1 | tee "${LOG}"
fuzztest::internal::assert_fuzzing_success "${LOG}"

# Check that we observe the edge coverage, not just random features.
fuzztest::internal::assert_regex_in_file "cov: [234] " "${LOG}"

echo "Running fuzzing for some number of iterations: ${TARGET_BINARY_DLOPEN}"
WD="${TEST_TMPDIR}/WD"
LOG="${TEST_TMPDIR}/log3"
export FUZZ_ME_PATH="${TARGET_DSO}"
fuzztest::internal::ensure_empty_dir "${WD}"
"${CENTIPEDE_BINARY}" --workdir "${WD}" \
  --binary \
  "LD_PRELOAD=${CENTIPEDE_RUNNER_NO_MAIN_SO} ${TARGET_BINARY_DLOPEN} @@" \
  --runner_dl_path_suffix "/fuzz_me.so" --coverage_binary "${TARGET_DSO}" \
  --objdump_path="${OBJDUMP}" \
  --num_runs=100 --fork_server=0 2>&1 | tee "${LOG}"
fuzztest::internal::assert_fuzzing_success "${LOG}"

# Check that we observe the edge coverage, not just random features.
fuzztest::internal::assert_regex_in_file "cov: [234] " "${LOG}"

echo "PASS"
