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

# Tests basic functionality for a target with multiple instrumented DSOs.
set -eu

source "$(dirname "$0")/../test_util.sh"


CENTIPEDE_TEST_SRCDIR="$(centipede::get_centipede_test_srcdir)"

centipede::maybe_set_var_to_executable_path \
  CENTIPEDE_BINARY "${CENTIPEDE_TEST_SRCDIR}/centipede"

centipede::maybe_set_var_to_executable_path \
  TARGET_BINARY "${CENTIPEDE_TEST_SRCDIR}/testing/multi_dso_target"

centipede::maybe_set_var_to_executable_path \
  LLVM_SYMBOLIZER "$(centipede::get_llvm_symbolizer_path)"


# Run fuzzing until the first crash.
WD="${TEST_TMPDIR}/WD"
LOG="${TEST_TMPDIR}/log"
centipede::ensure_empty_dir "${WD}"

"${CENTIPEDE_BINARY}" --binary="${TARGET_BINARY}" --workdir="${WD}" \
  --exit_on_crash=1 --seed=1 --log_features_shards=1 \
  --symbolizer_path="${LLVM_SYMBOLIZER}" \
  2>&1 |tee "${LOG}"

echo "Fuzzing DONE"

centipede::assert_regex_in_file "Batch execution failed:" "${LOG}"
centipede::assert_regex_in_file "Input bytes.*: fuzz" "${LOG}"
centipede::assert_regex_in_file "Symbolizing 2 instrumented DSOs" "${LOG}"
centipede::assert_regex_in_file "FUNC: LLVMFuzzerTestOneInput" "${LOG}"
centipede::assert_regex_in_file "FUNC: DSO" "${LOG}"

echo "PASS"
