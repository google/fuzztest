#!/bin/bash

# Copyright 2026 The FuzzTest Authors.
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

# Test running test_binary_for_engine_testing with Centipede.

set -eu

source "$(dirname "$0")/../test_fuzzing_util.sh"
source "$(dirname "$0")/../test_util.sh"

CENTIPEDE_TEST_SRCDIR="$(fuzztest::internal::get_centipede_test_srcdir)"

fuzztest::internal::maybe_set_var_to_executable_path \
  CENTIPEDE_BINARY "${CENTIPEDE_TEST_SRCDIR}/centipede"
fuzztest::internal::maybe_set_var_to_executable_path \
  TEST_BINARY_FOR_ENGINE_TESTING "${CENTIPEDE_TEST_SRCDIR}/testing/test_binary_for_engine_testing"

# --- Test 1: Run centipede directly with test_binary_for_engine_testing as target ---
echo "============ Running Test 1: Centipede -> test_binary_for_engine_testing"

FUNC1="test_engine_direct"
WD1="${TEST_TMPDIR}/${FUNC1}/WD"
LOG1="${TEST_TMPDIR}/${FUNC1}/log"
fuzztest::internal::ensure_empty_dir "${WD1}"

set +e
"${CENTIPEDE_BINARY}" \
  --binary="${TEST_BINARY_FOR_ENGINE_TESTING}" \
  --workdir="${WD1}" \
  --test_name="some_test" \
  --populate_binary_info=0 \
  --fork_server=0 \
  --persistent_mode=0 \
  --exit_on_crash \
  --symbolizer_path=/dev/null \
  > "${LOG1}" 2>&1
RC1=$?
set -e

cat "${LOG1}"

if [ $RC1 -eq 0 ]; then
  echo "Test 1 failed: Centipede exited with 0, expected non-zero exit code on crash"
  exit 1
fi

fuzztest::internal::assert_regex_in_file "Failure.*: some_failure_description" "${LOG1}"
echo "Test 1 PASSED"

# --- Test 2: Run test_binary_for_engine_testing directly with FUZZTEST_CENTIPEDE_BINARY_PATH ---
echo "============ Running Test 2: test_binary_for_engine_testing (controller) -> Centipede -> test_binary_for_engine_testing (worker)"

FUNC2="test_engine_via_env"
WD2="${TEST_TMPDIR}/${FUNC2}/WD"
LOG2="${TEST_TMPDIR}/${FUNC2}/log"
fuzztest::internal::ensure_empty_dir "${WD2}"

# Since we cannot pass --workdir to the controller easily (it hardcodes flags),
# we run it in a temporary directory so that default workdir (if any) is created there.
# We must set FUZZTEST_CENTIPEDE_BINARY_PATH when running TEST_BINARY_FOR_ENGINE_TESTING.
(
  cd "${WD2}"
  set +e
  FUZZTEST_CENTIPEDE_BINARY_PATH="${CENTIPEDE_BINARY}" "${TEST_BINARY_FOR_ENGINE_TESTING}" > "${LOG2}" 2>&1
  RC2=$?
  set -e

  cat "${LOG2}"

  if [ $RC2 -eq 0 ]; then
    echo "Test 2 failed: TEST_BINARY_FOR_ENGINE_TESTING exited with 0, expected non-zero exit code on crash"
    exit 1
  fi

  # The output of Centipede should be forwarded to LOG2 by system().
  fuzztest::internal::assert_regex_in_file "Failure.*: some_failure_description" "${LOG2}"
)
RC_SUB=$?

if [ $RC_SUB -ne 0 ]; then
  echo "Test 2 failed"
  exit 1
fi

echo "Test 2 PASSED"
echo "ALL TESTS PASSED"
