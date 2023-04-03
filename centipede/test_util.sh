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

# Prints "$@" and terminates the current shell.
function die() {
  echo "FATAL: $*" >&2
  # Kill our own shell or, if we're in a subshell, kill the parent (main) shell.
  kill $$
  # If we're in a subshell, exit it.
  exit 1
}

# Executes a command line specified in $@ with a file operation, e.g.
# `rm <file>`. If a bundled executable `fileutil` is available, passed the
# command to it for extended file handling capabilities. Otherwise, just
# executes the command.
function fileop() {
  "$@"
}

# Returns the path to Centipede TEST_SRCDIR subdirectory.
function centipede::get_centipede_test_srcdir() {
  set -u
  echo "${TEST_SRCDIR}/${TEST_WORKSPACE}/centipede"
}

function get_system_binary_path() {
  set -u
  local -r name=$1
  local path
  path="$(which "${name}")"
  if (( $? != 0 )); then
    die "${name} must be installed and findable via" \
      "PATH: use install_dependencies_debian.sh to fix"
  fi
  echo "${path}"
}

# Returns the path to llvm-symbolizer.
function centipede::get_llvm_symbolizer_path() {
  get_system_binary_path "llvm-symbolizer"
}

# Returns the path to objdump.
function centipede::get_objdump_path() {
  get_system_binary_path "objdump"
}

# If the var named "$1" is unset, then sets it to "$2". If the var is set,
# doesn't change it. In either case, verifies that the final value is a path to
# an executable file.
function centipede::maybe_set_var_to_executable_path() {
  local var_name="$1"
  # NOTE: `local -n` creates a reference to the var named "$1".
  local -n var_ref="$1"
  local path="$2"
  if [[ -n "${var_ref+x}" ]]; then
    echo "Not overriding ${var_name} -- already set to '${var_ref}'" >&2
  else
    echo "Setting ${var_name} to '${path}'" >&2
    var_ref="${path}"
  fi
  if ! [[ -x "${var_ref}" ]]; then
    die "Path '${var_ref}' doesn't exist or is not executable"
  fi
}

# Same as centipede::maybe_set_var_to_executable_path(), but "$2" should be
# a command line that builds the executable and prints its path to stdout.
# TODO(ussuri): Reduce code duplication with the above.
function centipede::maybe_set_var_to_built_executable_path() {
  local var_name="$1"
  # NOTE: `local -n` creates a reference to the var named "$1".
  local -n var_ref="$1"
  local bazel_build_cmd="$2"
  if [[ -n "${var_ref+x}" ]]; then
    echo "Not overriding ${var_name} -- already set to '${var_ref}'" >&2
  else
    echo "Setting ${var_name} to output of '${bazel_build_cmd}'" >&2
    var_ref="$(set -e; ${bazel_build_cmd})"
  fi
  if ! [[ -x "${var_ref}" ]]; then
    die "Path '${var_ref}' doesn't exist or is not executable"
  fi
}

# Makes sure that an empty directory "$1" exists. Works for local and CNS.
function centipede::ensure_empty_dir() {
  fileop mkdir -p "$1"
  fileop rm -R -f "${1:?}"/*
}

function _assert_regex_in_file_impl() {
  local -r regex="$1"
  local -r file="$2"
  local -r expected_found="$3"
  set -o pipefail
  if ! fileop ls "${file}" > /dev/null; then
    die "Expected file ${file} doesn't exist"
  fi
  local found
  if grep -q -- "${regex}" <(fileop cat "${file}"); then
    found=1
  else
    found=0
  fi
  if ((found != expected_found)); then
    echo
    echo ">>>>>>>>>> BEGIN ${file} >>>>>>>>>>"
    fileop cat "${file}"
    echo "<<<<<<<<<< END ${file} <<<<<<<<<<"
    echo
    if ((expected_found)); then
      die "^^^ File ${file} doesn't contain expected regex /${regex}/"
    else
      die "^^^ File ${file} contains unexpected regex /${regex}/"
    fi
  fi
  set +o pipefail
}

# Makes sure that string "$1" exists in file "$2". Works for local and CNS.
function centipede::assert_regex_in_file() {
  local -r regex="$1"
  local -r file="$2"
  _assert_regex_in_file_impl "${regex}" "${file}" 1
}

function centipede::assert_regex_not_in_file() {
  local -r regex="$1"
  local -r file="$2"
  _assert_regex_in_file_impl "${regex}" "${file}" 0
}

# For each of the logs in "$@", asserts that fuzzing started and successfully
# completed.
function centipede::assert_fuzzing_success() {
  for log in "$@"; do
    centipede::assert_regex_in_file "centipede.*init-done:" "${log}"
    centipede::assert_regex_in_file "centipede.*end-fuzz:" "${log}"
  done
}
