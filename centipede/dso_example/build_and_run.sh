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

# This script demonstrates how to use Centipede for the following use case:
# * The code we want to fuzz resides in a separate shared library.
# * (optionally) the shared library needs to be built with GCC and is thus
#   limited to using the legacy trace-pc instrumentation.
# * The main binary is not instrumented. It passes inputs to the library.
# * The instrumented library is dlopen-ed by the main binary.

# Run this script in its own directory.
set -ue

echo "Building Centipede and copying files to /tmp"
cd ..
bazel build -c opt //...
cp -vf bazel-bin/{centipede,centipede_runner_no_main.so} /tmp
cd -

# The following instructions should work both with GCC and Clang.
CC=gcc # or clang
CXX=g++ # or clang++

echo "CC=${CC} CXX=${CXX}"

# Build the shared library with the coverage instrumentation.
# Here we use the legacy trace-pc instrumentation supported by GCC and Clang.
# https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs.
# But you can use other instrumentation as well.
echo "Building the instrumented shared library"
${CC} -O2 -g -fPIC -shared fuzz_me.cc -fsanitize-coverage=trace-pc -o fuzz_me.so

# Build the main binary without instrumentation.
echo "Building the non-instrumented binary"
${CXX} -O2 -g main.cc -o main_executable

echo "Preparing to run fuzzing"
rm -rf /tmp/wd
mkdir /tmp/wd

# Run fuzzing.
# The centipede run-time is LD_PRELOAD-ed.
# The instrumented library fuzz_me.so is `dlopen()`-ed.
echo "Fuzzing until the first crash"
/tmp/centipede --workdir=/tmp/wd \
  --binary="LD_PRELOAD=/tmp/centipede_runner_no_main.so FUZZ_ME_PATH=./fuzz_me.so ./main_executable @@" \
  --exit_on_crash=1 \
  --coverage_binary="${PWD}/fuzz_me.so" --runner_dl_path_suffix="/fuzz_me.so"
