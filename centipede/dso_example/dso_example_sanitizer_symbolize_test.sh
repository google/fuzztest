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

# Tests the stack symbolization of the main binary when running with sanitizers.

set -eu

source "$(dirname "$0")/../test_util.sh"

CENTIPEDE_TEST_SRCDIR="$(centipede::get_centipede_test_srcdir)"

centipede::maybe_set_var_to_executable_path \
    TARGET_BINARY "${CENTIPEDE_TEST_SRCDIR}/dso_example/main"

INPUT="${TEST_TMPDIR}/input"
LOG="${TEST_TMPDIR}/log"

echo -n 'FUZ' > "${INPUT}"
unset TEST_WARNINGS_OUTPUT_FILE
export ASAN_OPTIONS='handle_abort=2'
export MSAN_OPTIONS='handle_abort=2'
export TSAN_OPTIONS='handle_abort=2'
export CENTIPEDE_RUNNER_FLAGS=":use_cmp_features:"
"${TARGET_BINARY}" "${INPUT}" |& tee "${LOG}"

# Check that sanitizer reports the crash
centipede::assert_regex_in_file "ERROR: .*Sanitizer:" "${LOG}"
# Check that the intended stack location is symbolized and printed
centipede::assert_regex_in_file "#0 .* in FuzzMe" "${LOG}"

echo "PASS"
