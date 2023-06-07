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
  TARGET_BINARY "${CENTIPEDE_TEST_SRCDIR}/testing/expensive_startup_fuzz_target"

WD="${TEST_TMPDIR}/WD"
LOG="${TEST_TMPDIR}/log"

# Fuzz the target for a bit with callstacks and paths.
# Ensure that we don't see coverage from the Startup() function.
centipede::ensure_empty_dir "${WD}"
"${CENTIPEDE_BINARY}" --binary="${TARGET_BINARY}" --workdir="${WD}" \
  --num_runs=10000 --callstack_level=10 --path_level=10 2>&1 |tee "${LOG}"

centipede::assert_regex_in_file "end-fuzz:.*cov: 1 " "${LOG}"
centipede::assert_regex_in_file "end-fuzz:.*stk: 2 " "${LOG}"
centipede::assert_regex_in_file "end-fuzz:.*path: 1 " "${LOG}"
centipede::assert_regex_not_in_file "end-fuzz:.*cmp" "${LOG}"
centipede::assert_regex_not_in_file "end-fuzz:.*df" "${LOG}"

echo "PASS"
