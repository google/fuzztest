#!/bin/bash

# Script for generating fuzztest.bazelrc.

set -euf -o pipefail

echo "### DO NOT EDIT. Generated file.
#
# To regenerate, run the following from your project's workspace:
#
#  bazel run @com_google_fuzztest//bazel:setup_configs > fuzztest.bazelrc
#
# And don't forget to add the following to your project's .bazelrc:
#
#  try-import %workspace%/fuzztest.bazelrc
"

echo "
### Common options.
#
# Do not use directly.

# Compile and link with Address Sanitizer (ASAN).
build:fuzztest-common --linkopt=-fsanitize=address
build:fuzztest-common --copt=-fsanitize=address

# Standard define for \"ifdef-ing\" any fuzz test specific code.
build:fuzztest-common --copt=-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

# In fuzz tests, we want to catch assertion violations even in optimized builds.
build:fuzztest-common --copt=-UNDEBUG

# Enable libc++ assertions.
# See https://libcxx.llvm.org/UsingLibcxx.html#enabling-the-safe-libc-mode
build:fuzztest-common --copt=-D_LIBCPP_ENABLE_ASSERTIONS=1
"

echo "
### FuzzTest build configuration.
#
# Use with: --config=fuzztest

build:fuzztest --config=fuzztest-common

# Link statically.
build:fuzztest --dynamic_mode=off

# We rely on the following flag instead of the compiler provided
# __has_feature(address_sanitizer) to know that we have an ASAN build even in
# the uninstrumented runtime.
build:fuzztest --copt=-DADDRESS_SANITIZER
"

REPO_NAME="${1}"
# When used in the fuzztest repo itself.
if [ ${REPO_NAME} == "@" ]; then
  FUZZTEST_FILTER="//fuzztest:"
  CENTIPEDE_FILTER="//centipede:"
# When used in client repo.
elif [ ${REPO_NAME} == "@com_google_fuzztest" ]; then
  FUZZTEST_FILTER="fuzztest/.*"
  CENTIPEDE_FILTER="centipede/.*"
else
  echo "Unexpected repo name: ${REPO_NAME}"
  exit 1
fi

echo "# We apply coverage tracking instrumentation to everything but the
# FuzzTest framework itself (including GoogleTest and GoogleMock).
build:fuzztest --per_file_copt=+//,-${FUZZTEST_FILTER},-${CENTIPEDE_FILTER},-googletest/.*,-googlemock/.*@-fsanitize-coverage=inline-8bit-counters,-fsanitize-coverage=trace-cmp,-fsanitize-coverage=pc-table
"

# Do not use the extra configurations below, unless you know what you're doing.

EXTRA_CONFIGS="${EXTRA_CONFIGS:-none}"

if [[ ${EXTRA_CONFIGS} == *"libfuzzer"* ]]; then

# Find llvm-config.
LLVM_CONFIG=$(command -v llvm-config    ||
              command -v llvm-config-15 ||
              command -v llvm-config-14 ||
              command -v llvm-config-13 ||
              command -v llvm-config-12 ||
              echo "")

if [[ -z "${LLVM_CONFIG}" ]]; then
  echo "ERROR: Couldn't generate config, because cannot find llvm-config."
  echo ""
  echo "Please install clang and llvm, e.g.:"
  echo ""
  echo "  sudo apt install clang llvm"
  exit 1
fi

echo "
### libFuzzer compatibility mode.
#
# Use with: --config=libfuzzer

build:libfuzzer --config=fuzztest-common
build:libfuzzer --copt=-DFUZZTEST_COMPATIBILITY_MODE
build:libfuzzer --copt=-fsanitize=fuzzer-no-link
build:libfuzzer --linkopt=$(find $(${LLVM_CONFIG} --libdir) -name libclang_rt.fuzzer_no_main-x86_64.a | head -1)
"

fi # libFuzzer


# OSS-Fuzz
if [[ -n ${FUZZING_ENGINE:-} && -n ${SANITIZER:-} ]]; then
echo "
### OSS-Fuzz compatibility mode.
#
# Use with: --config=oss-fuzz
build:oss-fuzz --copt=-DFUZZTEST_COMPATIBILITY_MODE
build:oss-fuzz --dynamic_mode=off
build:oss-fuzz --action_env=CC=${CC}
build:oss-fuzz --action_env=CXX=${CXX}
"

ossfuz_flag_to_bazel_config_flag()
{
  bazel_flag=$1
  flag=$2

  # When we have something along -fno-sanitize-recover=bool,array,...,.. we
  # need to split them out and write each assignment without use of commas. Otherwise
  # the per_file_copt option splits the comma string with spaces, which causes the
  # build command to be erroneous.
  if [[ $flag == *","* && $flag == *"="* ]]; then
    # Split from first occurrence of equals.
    flag_split_over_equals=(${flag//=/ })
    lhs=${flag_split_over_equals[0]}
    comma_values=($(echo ${flag_split_over_equals[1]} | tr ',' " "))
    for val in "${comma_values[@]}"; do
      echo "build:oss-fuzz $bazel_flag=${lhs}=${val}"
    done
  else
    if [[ $flag != *"no-as-needed"* ]]; then
      # Flags captured here include -fsanitize=fuzzer-no-link, -fsanitize=addresss.
      echo "build:oss-fuzz $bazel_flag=$flag"
    fi
  fi

}
for flag in $CFLAGS; do
  echo "$(ossfuz_flag_to_bazel_config_flag "--conlyopt" $flag)"
  echo "$(ossfuz_flag_to_bazel_config_flag "--linkopt" $flag)"
done

for flag in $CXXFLAGS; do
  echo "$(ossfuz_flag_to_bazel_config_flag "--cxxopt" $flag)"
  echo "$(ossfuz_flag_to_bazel_config_flag "--linkopt" $flag)"
done

if [ "$SANITIZER" = "undefined" ]; then
  echo "build:oss-fuzz --linkopt=$(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1)"
fi
if [ "$FUZZING_ENGINE" = "libfuzzer" ]; then
  echo "build:oss-fuzz --linkopt=$(find $(llvm-config --libdir) -name libclang_rt.fuzzer_no_main-x86_64.a | head -1)"
fi

# AFL version in oss-fuzz does not support LLVMFuzzerRunDriver. It must be updated first.
#if [ "$FUZZING_ENGINE" = "afl" ]; then
#  echo "build:oss-fuzz --linkopt=${LIB_FUZZING_ENGINE}"
#fi
fi # OSS-Fuzz
