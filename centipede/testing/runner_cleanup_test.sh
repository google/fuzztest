#!/bin/bash

# Copyright 2025 The Centipede Authors.
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

# Tests cleanup of features for ignored tests.

set -eu

source "$(dirname "$0")/../test_util.sh"

CENTIPEDE_TEST_SRCDIR="$(fuzztest::internal::get_centipede_test_srcdir)"

echo "======== Check ignored tests don't count features"

CENTIPEDE_TEST_SRCDIR="$(fuzztest::internal::get_centipede_test_srcdir)"
fuzztest::internal::maybe_set_var_to_executable_path \
  CENTIPEDE_BINARY "${CENTIPEDE_TEST_SRCDIR}/centipede"

fuzztest::internal::maybe_set_var_to_executable_path \
  REJECTING_BINARY "${CENTIPEDE_TEST_SRCDIR}/testing/random_rejecting_fuzz_target"

WD="${TEST_TMPDIR}/WD"
LOG="${TEST_TMPDIR}/log"

"${CENTIPEDE_BINARY}" --binary="${REJECTING_BINARY}" --workdir="${WD}" \
  --num_runs=10000  2>&1 |tee "${LOG}"

fuzztest::internal::assert_regex_not_in_file "usr1: " "${LOG}"

echo "PASS"
