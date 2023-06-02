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

# Tests __attribute__((section("__centipede_extra_features")))

set -eu

source "$(dirname "$0")/../test_util.sh"

CENTIPEDE_TEST_SRCDIR="$(centipede::get_centipede_test_srcdir)"

centipede::maybe_set_var_to_executable_path \
  CENTIPEDE_BINARY "${CENTIPEDE_TEST_SRCDIR}/centipede"

centipede::maybe_set_var_to_executable_path \
  TARGET_BINARY "${CENTIPEDE_TEST_SRCDIR}/testing/user_defined_features_target"

WD="${TEST_TMPDIR}/WD"
LOG="${TEST_TMPDIR}/log"

"${TARGET_BINARY}" 2>&1 | tee "${LOG}"

centipede::assert_regex_in_file \
  "section..__centipede_extra_features.. detected with 10000 elements" "${LOG}"

centipede::ensure_empty_dir "${WD}"
"${CENTIPEDE_BINARY}" --binary="${TARGET_BINARY}" --workdir="${WD}" \
  --num_runs=10000  2>&1 |tee "${LOG}"

centipede::assert_regex_in_file "usr0: [0-9]\{3,\} " "${LOG}"
centipede::assert_regex_in_file "usr1: [0-9]\{3,\} " "${LOG}"
centipede::assert_regex_not_in_file "usr2: " "${LOG}"
centipede::assert_regex_not_in_file "usr3: " "${LOG}"

echo "PASS"
