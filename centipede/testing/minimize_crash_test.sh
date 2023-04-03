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

# Tests the --minimize_crash flag.

set -eu

source "$(dirname "$0")/../test_util.sh"

CENTIPEDE_TEST_SRCDIR="$(centipede::get_centipede_test_srcdir)"

centipede::maybe_set_var_to_executable_path \
  CENTIPEDE_BINARY "${CENTIPEDE_TEST_SRCDIR}/centipede"

centipede::maybe_set_var_to_executable_path \
  TARGET_BINARY "${CENTIPEDE_TEST_SRCDIR}/testing/minimize_me_fuzz_target"

WD="${TEST_TMPDIR}/WD"
LOG="${TEST_TMPDIR}/log"

# Prepare the crasher input.
CRASHER="${TEST_TMPDIR}/crasher"
echo -n '?f???u???z?' > "${CRASHER}"

# Run minimization loop
centipede::ensure_empty_dir "${WD}"
"${CENTIPEDE_BINARY}" --binary="${TARGET_BINARY}" --workdir="${WD}" \
  --minimize_crash="${CRASHER}" --seed=1 --num_runs=100000 \
  2>&1 |tee "${LOG}"

# Check that the log contains the 5-byte crash input.
# The 3 middle bytes of it should be 'fuz'.
# The minimization for this test target is not guaranteed to produce
# some specific 5-byte input.
centipede::assert_regex_in_file "Crasher: size: 5: .*fuz.*" "${LOG}"

# Check that we actually have a 5-byte-long file in "${WD}/crashes".
find "${WD}/crashes" -size 5c

# Cats a large crasher consisting of 2*n+5 bytes to stdout.
# $1: n
make_large_crasher() {
  echo -n .f;
  head -c "${1}" /dev/urandom
  echo -n u
  head -c "${1}" /dev/urandom
  echo -n z.
}

# Create a 105-byte crasher.
make_large_crasher 50 > "${CRASHER}"

# Run minimization on the large crasher in multiple threads.
centipede::ensure_empty_dir "${WD}"
"${CENTIPEDE_BINARY}" --binary="${TARGET_BINARY}" --workdir="${WD}" \
  --minimize_crash="${CRASHER}" --seed=1 --num_runs=100000 -j 5 \
  2>&1 |tee "${LOG}"

# Check that we found crashers of 99 bytes or less.
# This is not much given that the original crasher is 105 bytes,
# but otherwise we risk making this test too flaky.
centipede::assert_regex_in_file "Crasher: size: [0-9]\{1,2\}:" "${LOG}"

echo "PASS"
