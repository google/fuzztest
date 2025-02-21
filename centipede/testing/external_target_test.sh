#!/bin/bash

# Copyright 2024 The Centipede Authors.
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

set -euo pipefail

source "$(dirname "$0")/../test_util.sh"

CENTIPEDE_TEST_SRCDIR="$(centipede::get_centipede_test_srcdir)"

centipede::maybe_set_var_to_executable_path \
  CENTIPEDE_BINARY "${CENTIPEDE_TEST_SRCDIR}/centipede"
centipede::maybe_set_var_to_executable_path \
  LLVM_SYMBOLIZER "$(centipede::get_llvm_symbolizer_path)"
centipede::maybe_set_var_to_executable_path \
  SERVER_BINARY "${CENTIPEDE_TEST_SRCDIR}/testing/external_target_server"
centipede::maybe_set_var_to_executable_path \
  TARGET_BINARY "${CENTIPEDE_TEST_SRCDIR}/testing/external_target"

readonly WD="${TEST_TMPDIR}/WD"
readonly LOG="${TEST_TMPDIR}/log"
centipede::ensure_empty_dir "${WD}"

TARGET_PORT=$(centipede::get_random_free_port)
readonly TARGET_PORT

echo "Starting the server binary using port ${TARGET_PORT}..."
env CENTIPEDE_RUNNER_FLAGS=":use_auto_dictionary:use_cmp_features:use_pc_features:" \
  TARGET_PORT="${TARGET_PORT}" \
  "${SERVER_BINARY}" &
readonly SERVER_PID="$!"
trap "kill ${SERVER_PID} || true" SIGINT SIGTERM EXIT

echo "Running Centipede to fuzz the target binary ..."
env TARGET_PORT="${TARGET_PORT}" \
  "${CENTIPEDE_BINARY}" --binary="${TARGET_BINARY}" --workdir="${WD}" \
  --coverage_binary="${SERVER_BINARY}" --symbolizer_path="${LLVM_SYMBOLIZER}" \
  --exit_on_crash=1 --seed=1 --log_features_shards=1 \
  2>&1 | tee "${LOG}" || true

# Check that Centipede finds the crashing input.
centipede::assert_regex_in_file "Input bytes.*: Secret" "${LOG}"
# Check that Centipede uses the coverage features of the external target server.
centipede::assert_regex_in_file "EDGE: .*external_target_server.cc:" "${LOG}"
