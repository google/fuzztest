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

# Tests output format of Centipede. Uses regexes to verify if the output
# matches the format expected by ClusterFuzz.

set -eu

source "$(dirname "$0")/../test_util.sh"

# Centipede and target binaries.
declare centipede
centipede="$(centipede::get_centipede_test_srcdir)/centipede"
declare target
target="$(centipede::get_centipede_test_srcdir)/testing/clusterfuzz_format_target"
declare sanitized_target
sanitized_target="$(centipede::get_centipede_test_srcdir)/testing/clusterfuzz_format_sanitized_target"

# Input files.
declare -r oom="${TEST_TMPDIR}/oom"
declare -r uaf="${TEST_TMPDIR}/uaf"
declare -r slo="${TEST_TMPDIR}/slo"

echo -n oom > "${oom}"  # Triggers out-of-memory.
echo -n uaf > "${uaf}"  # Triggers heap-use-after-free.
echo -n slo > "${slo}"  # Triggers heap-use-after-free.

# Shorthand to run centipede with necessary flags.
abort_test_fuzz() {
  set -x
  "${centipede}" \
    --workdir="${WD}" \
    --binary="${target}" --symbolizer_path=/dev/null \
    --extra_binaries="${sanitized_target}" \
    --address_space_limit_mb=4096 \
    --timeout_per_input=5 \
    "$@" 2>&1
  set +x
}

# Tests fuzzing with a target that crashes.
test_crashing_target() {
  local -r input_file="$1"
  local -r expected_regex="$2"
  local -r input_file_basename="$(basename "${input_file}")"
  local -r FUNC="${FUNCNAME[0]}"
  local -r WD="${TEST_TMPDIR}/${FUNC}/WD"
  local -r TMPCORPUS="${TEST_TMPDIR}/${FUNC}/C"
  local -r LOG="${TEST_TMPDIR}/${FUNC}/log_${input_file_basename}"
  centipede::ensure_empty_dir "${WD}"
  centipede::ensure_empty_dir "${TMPCORPUS}"

  # Create a corpus with one crasher and one other input.
  cp "$1" "${TMPCORPUS}"  # Triggers an error.
  echo -n "foo" >"${TMPCORPUS}/foo"     # Just some input.
  abort_test_fuzz --export_corpus_from_local_dir="${TMPCORPUS}"

  # Run fuzzing with num_runs=0, i.e. only run the inputs from the corpus.
  # Expecting a crash to be observed and reported.
  abort_test_fuzz --num_runs=0 | tee "${LOG}"

  # Sanity check. Validate failure input bytes.
  centipede::assert_regex_in_file \
    "^Input bytes[ \t]*: ${input_file_basename}" "${LOG}"

  # The following formats are required by ClusterFuzz.
  # Validate failure reason format.
  centipede::assert_regex_in_file \
    "^CRASH LOG: ${expected_regex}" "${LOG}"
  # Validate input saving format.
  centipede::assert_regex_in_file \
    '^Saving input to: .\+/crashes/.\+' "${LOG}"
}

# Check if the following crash logs are in the format expected by ClusterFuzz.
# This input triggers ASAN heap-use-after-free error.
echo ======== Check UAF crash log format.
test_crashing_target "${uaf}" '.*ERROR: AddressSanitizer: heap-use-after-free'

# This input triggers out-of-memory error.
echo ======== Check OOM crash log format.
test_crashing_target "${oom}" '========= RSS limit exceeded:'

# This input triggers timeout.
echo ======== Check timeout crash log format.
test_crashing_target "${slo}" '========= Per-input timeout exceeded:'

echo "PASS"
