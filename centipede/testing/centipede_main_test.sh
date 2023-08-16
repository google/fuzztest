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

# Test common scenarios of Centipede.

set -eu

source "$(dirname "$0")/../test_fuzzing_util.sh"
source "$(dirname "$0")/../test_util.sh"

CENTIPEDE_TEST_SRCDIR="$(centipede::get_centipede_test_srcdir)"

# The following variables can be overridden externally by passing --test_env to
# the build command, e.g. --test_env=EXAMPLE_TARGET_BINARY="/some/path".
centipede::maybe_set_var_to_executable_path \
  CENTIPEDE_BINARY "${CENTIPEDE_TEST_SRCDIR}/centipede"
centipede::maybe_set_var_to_executable_path \
  TEST_TARGET_BINARY "${CENTIPEDE_TEST_SRCDIR}/testing/test_fuzz_target"
centipede::maybe_set_var_to_executable_path \
  ABORT_TEST_TARGET_BINARY "${CENTIPEDE_TEST_SRCDIR}/testing/abort_fuzz_target"
centipede::maybe_set_var_to_executable_path \
  LLVM_SYMBOLIZER "$(centipede::get_llvm_symbolizer_path)"

# Shorthand for centipede --binary=test_fuzz_target
test_fuzz() {
  set -x
  "${CENTIPEDE_BINARY}" \
    --binary="${TEST_TARGET_BINARY}" --symbolizer_path=/dev/null \
    --print_config \
    "$@" 2>&1
  set +x
}

# Shorthand for centipede --binary=abort_fuzz_target
abort_test_fuzz() {
  set -x
  "${CENTIPEDE_BINARY}" \
    --binary="${ABORT_TEST_TARGET_BINARY}" --symbolizer_path=/dev/null \
    --print_config \
    "$@" 2>&1
  set +x
}

# Tests how the debug symbols are shown in the output.
test_debug_symbols() {
  FUNC="${FUNCNAME[0]}"
  WD="${TEST_TMPDIR}/${FUNC}/WD"
  TMPCORPUS="${TEST_TMPDIR}/${FUNC}/C"
  LOG="${TEST_TMPDIR}/${FUNC}/log"
  centipede::ensure_empty_dir "${WD}"
  centipede::ensure_empty_dir "${TMPCORPUS}"

  echo -n "func1" >"${TMPCORPUS}/func1"     # induces a call to SingleEdgeFunc.
  echo -n "func2-A" >"${TMPCORPUS}/func2-A" # induces a call to MultiEdgeFunc.

  echo "============ ${FUNC}: run for the first time, with empty seed corpus, with feature logging"
  test_fuzz --log_features_shards=1 --workdir="${WD}" --seed=1 --num_runs=1000 \
    --symbolizer_path="${LLVM_SYMBOLIZER}" | tee "${LOG}"
  centipede::assert_regex_in_file 'Custom mutator detected: will use it' "${LOG}"
  # Note: the test assumes LLVMFuzzerTestOneInput is defined on a specific line.
  centipede::assert_regex_in_file "FUNC: LLVMFuzzerTestOneInput .*testing/test_fuzz_target.cc:62" "${LOG}"
  centipede::assert_regex_in_file "EDGE: LLVMFuzzerTestOneInput .*testing/test_fuzz_target.cc" "${LOG}"

  echo "============ ${FUNC}: add func1/func2-A inputs to the corpus."
  test_fuzz --workdir="${WD}" --export_corpus_from_local_dir="${TMPCORPUS}"

  echo "============ ${FUNC}: run again, append to the same LOG file."
  # TODO(b/282845630): Passing `--num_runs=1` only to trigger telemetry dumping.
  #  Change to `--num_runs=0` after the bug is fixed.
  test_fuzz --log_features_shards=1 --workdir="${WD}" --seed=1 --num_runs=1 \
    --telemetry_frequency=1 --symbolizer_path="${LLVM_SYMBOLIZER}" 2>&1 \
    | tee -a "${LOG}"
  centipede::assert_regex_in_file "FUNC: SingleEdgeFunc" "${LOG}"
  centipede::assert_regex_in_file "FUNC: MultiEdgeFunc" "${LOG}"
  centipede::assert_regex_in_file "EDGE: MultiEdgeFunc" "${LOG}"

  echo "============ ${FUNC}: checking the coverage report"
  for COV_REPORT_TYPE in "initial" "latest"; do
    COV_REPORT="${WD}/coverage-report-$(basename "${TEST_TARGET_BINARY}").000000.${COV_REPORT_TYPE}.txt"
    centipede::assert_regex_in_file "Generate coverage report:.*${COV_REPORT}" "${LOG}"
    centipede::assert_regex_in_file "FULL: SingleEdgeFunc" "${COV_REPORT}"
    centipede::assert_regex_in_file "PARTIAL: LLVMFuzzerTestOneInput" "${COV_REPORT}"
  done

  echo "============ ${FUNC}: run w/o the symbolizer, everything else should still work."
  centipede::ensure_empty_dir "${WD}"
  test_fuzz --workdir="${WD}" --seed=1 --num_runs=1000 \
    --symbolizer_path=/dev/null | tee "${LOG}"
  centipede::assert_regex_in_file "Symbolizer unspecified: debug symbols will not be used" "${LOG}"
  centipede::assert_regex_in_file "end-fuzz:" "${LOG}"
}

# Creates workdir ($1) and tests how dictionaries are loaded.
test_dictionary() {
  FUNC="${FUNCNAME[0]}"
  WD="${TEST_TMPDIR}/${FUNC}/WD"
  TMPCORPUS="${TEST_TMPDIR}/${FUNC}/C"
  DICT="${TEST_TMPDIR}/${FUNC}/dict"
  LOG="${TEST_TMPDIR}/${FUNC}/log"
  centipede::ensure_empty_dir "${WD}"
  centipede::ensure_empty_dir "${TMPCORPUS}"

  echo "============ ${FUNC}: testing non-existing dictionary file"
  test_fuzz --workdir="${WD}" --num_runs=0 --dictionary=/dev/null | tee "${LOG}"
  centipede::assert_regex_in_file "Empty or corrupt dictionary file: /dev/null" "${LOG}"

  echo "============ ${FUNC}: testing plain text dictionary file"
  echo '"blah"' >"${DICT}"
  echo '"boo"' >>"${DICT}"
  echo '"bazz"' >>"${DICT}"
  cat "${DICT}"
  test_fuzz --workdir="${WD}" --num_runs=0 --dictionary="${DICT}" | tee "${LOG}"
  centipede::assert_regex_in_file "Loaded 3 dictionary entries from AFL/libFuzzer dictionary ${DICT}" "${LOG}"

  echo "============ ${FUNC}: creating a binary dictionary file with 2 entries"
  echo "foo" >"${TMPCORPUS}"/foo
  echo "bat" >"${TMPCORPUS}"/binary
  centipede::ensure_empty_dir "${WD}"
  test_fuzz --workdir="${WD}" --export_corpus_from_local_dir "${TMPCORPUS}"
  cp "${WD}/corpus.000000" "${DICT}"

  echo "============ ${FUNC}: testing binary dictionary file"
  centipede::ensure_empty_dir "${WD}"
  test_fuzz --workdir="${WD}" --num_runs=0 --dictionary="${DICT}" | tee "${LOG}"
  centipede::assert_regex_in_file "Loaded 2 dictionary entries from ${DICT}" "${LOG}"
}

# Creates workdir ($1) and tests --for_each_blob.
test_for_each_blob() {
  FUNC="${FUNCNAME[0]}"
  WD="${TEST_TMPDIR}/${FUNC}/WD"
  TMPCORPUS="${TEST_TMPDIR}/${FUNC}/C"
  LOG="${TEST_TMPDIR}/${FUNC}/log"
  centipede::ensure_empty_dir "${WD}"
  centipede::ensure_empty_dir "${TMPCORPUS}"

  echo "FoO" >"${TMPCORPUS}"/a
  echo "bAr" >"${TMPCORPUS}"/b

  test_fuzz --workdir="${WD}" --export_corpus_from_local_dir "${TMPCORPUS}"
  echo "============ ${FUNC}: test for_each_blob"
  test_fuzz --for_each_blob="cat %P" "${WD}"/corpus.000000 | tee "${LOG}"
  centipede::assert_regex_in_file "Running 'cat %P' on ${WD}/corpus.000000" "${LOG}"
  centipede::assert_regex_in_file FoO "${LOG}"
  centipede::assert_regex_in_file bAr "${LOG}"
}

# Creates workdir ($1) and tests --use_pcpair_features.
test_pcpair_features() {
  FUNC="${FUNCNAME[0]}"
  WD="${TEST_TMPDIR}/${FUNC}/WD"
  LOG="${TEST_TMPDIR}/${FUNC}/log"
  centipede::ensure_empty_dir "${WD}"

  echo "============ ${FUNC}: fuzz with --use_pcpair_features"
  test_fuzz --workdir="${WD}" --use_pcpair_features --num_runs=10000 \
    --symbolizer_path="${LLVM_SYMBOLIZER}" | tee "${LOG}"
  centipede::assert_regex_in_file "end-fuzz.*pair: [^0]" "${LOG}"

  echo "============ ${FUNC}: fuzz with --use_pcpair_features w/o symbolizer"
  test_fuzz --workdir="${WD}" --use_pcpair_features --num_runs=10000 \
    --symbolizer_path=/dev/null | tee "${LOG}"
  centipede::assert_regex_in_file "end-fuzz.*pair: [^0]" "${LOG}"
}

centipede::test_crashing_target abort_test_fuzz "foo" "AbOrT" "I AM ABOUT TO ABORT"
test_debug_symbols
test_dictionary
test_for_each_blob
test_pcpair_features

echo "PASS"
