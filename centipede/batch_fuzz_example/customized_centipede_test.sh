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

CENTIPEDE_TEST_SRCDIR="$(centipede::get_centipede_test_srcdir)"

centipede::maybe_set_var_to_executable_path \
  CENTIPEDE_BINARY "${CENTIPEDE_TEST_SRCDIR}/batch_fuzz_example/customized_centipede"
centipede::maybe_set_var_to_executable_path \
  TARGET_BINARY "${CENTIPEDE_TEST_SRCDIR}/batch_fuzz_example/batch_fuzz_target"

# Shorthand for customized_centipede --binary=batch_fuzz_target.
batch_fuzz() {
  set -x
  "${CENTIPEDE_BINARY}" \
    --binary="${TARGET_BINARY}" --symbolizer_path=/dev/null \
    --print_runner_log \
    "$@" 2>&1
  set +x
}

# TODO: Refactoring run_some_fuzzing and test_crashing_target into test_util.
# Creates a workdir and performs some basic fuzzing runs.
run_some_fuzzing() {
  FUNC="${FUNCNAME[0]}"
  WD="${TEST_TMPDIR}/${FUNC}/WD"
  LOG="${TEST_TMPDIR}/${FUNC}/log"
  centipede::ensure_empty_dir "${WD}"

  echo "============ ${FUNC}: First run: 100 runs in batches of 7"
  batch_fuzz -workdir="${WD}" -num_runs 100 --batch_size=7 | tee "${LOG}"
  centipede::assert_regex_in_file '\[S0.100\] end-fuzz:' "${LOG}" # Check the number of runs.
  centipede::assert_fuzzing_success "${LOG}"
  ls -l "${WD}"

  echo "============ ${FUNC}: Second run: 300 runs in batches of 8"
  batch_fuzz -workdir="${WD}" -num_runs 300 --batch_size=8 | tee "${LOG}"
  centipede::assert_regex_in_file '\[S0.300\] end-fuzz:' "${LOG}" # Check the number of runs.
  centipede::assert_fuzzing_success "${LOG}"
  ls -l "${WD}"

  N_SHARDS=3
  echo "============ ${FUNC}: Running ${N_SHARDS} shards"
  for ((s = 0; s < "${N_SHARDS}"; s++)); do
    batch_fuzz --workdir="${WD}" -num_runs 100 --first_shard_index="$s" \
      --total_shards="${N_SHARDS}" | tee "${LOG}.${s}" &
  done
  wait
  echo "============ ${FUNC}: Shards finished, checking output"
  for ((s = 0; s < "${N_SHARDS}"; s++)); do
    grep -q "centipede.cc.*end-fuzz:" "${LOG}.${s}"
  done
  centipede::assert_fuzzing_success "${LOG}".*

  ls -l "${WD}"
}

# Tests fuzzing with a target that crashes.
test_crashing_target() {
  FUNC="${FUNCNAME[0]}"
  WD="${TEST_TMPDIR}/${FUNC}/WD"
  TMPCORPUS="${TEST_TMPDIR}/${FUNC}/C"
  LOG="${TEST_TMPDIR}/${FUNC}/log"
  centipede::ensure_empty_dir "${WD}"
  centipede::ensure_empty_dir "${TMPCORPUS}"

  # Create a corpus with one crasher and one other input.
  echo -n "fuz" >"${TMPCORPUS}/fuz" # induces abort in the target.
  echo -n "foo" >"${TMPCORPUS}/foo" # just some input.
  batch_fuzz --workdir="${WD}" --export_corpus_from_local_dir="${TMPCORPUS}"

  ls -l "${WD}"

  # Run fuzzing with num_runs=0, i.e. only run the inputs from the corpus.
  # Expecting a crash to be observed and reported.
  batch_fuzz --workdir="${WD}" --num_runs=0 | tee "${LOG}"
  centipede::assert_regex_in_file "2 inputs to rerun" "${LOG}"
  centipede::assert_regex_in_file "Batch execution failed:" "${LOG}"

  # Comes from batch_fuzz_target
  centipede::assert_regex_in_file "Catch you" "${LOG}"
  ls -l "${WD}"
}

run_some_fuzzing
test_crashing_target

echo "PASS"
