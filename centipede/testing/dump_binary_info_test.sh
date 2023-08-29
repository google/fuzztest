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
set -eu

source "$(dirname "$0")/../test_util.sh"

binary="$(centipede::get_centipede_test_srcdir)/testing/multi_dso_target"

pc_table="${TEST_TMPDIR}/pc_table"
cf_table="${TEST_TMPDIR}/cf_table"
dso_table="${TEST_TMPDIR}/dso_table"

# Dump the binary info tables on disk
CENTIPEDE_RUNNER_FLAGS=":dump_binary_info:arg1=${pc_table}:arg2=${cf_table}:arg3=${dso_table}:" \
  "${binary}"

# Check the pc table size.
size=$(stat -c %s "${pc_table}")
echo "pc table file size: ${size}"
(( size >= 1 )) || die "pc table is too small: ${size}"

# Check the cf table size
size=$(stat -c %s "${cf_table}")
echo "cf table size: ${size}"
(( size >= 1 )) || die "cf table is too small: ${size}"

# Check the DSO table size (in lines)
cat "${dso_table}"
size=$(cat "${dso_table}" | wc -l)
echo "dso table size: ${size}"
(( size == 2 )) || die "dso table should have exactly 2 entries"
centipede::assert_regex_in_file "lib.so [1-9]" "${dso_table}"
# Check the path to main binary in the dso table.
# It may differe from $binary but it should point to the same file.
binary_path=$(grep -v '.so ' "${dso_table}" | grep -o "^[^ ]\+")
cmp "${binary_path}" "${binary}" \
  || die "the path to main binary in dso table is wrong"

# Check the DSO path in the dso table.
so_path=$(grep '.so ' "${dso_table}" | grep -o "^[^ ]\+")
[[ -f "${so_path}" ]] || die "dso path from dso table is wrong"

echo "PASS"
