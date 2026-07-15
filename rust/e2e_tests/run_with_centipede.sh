#!/bin/bash
#
# Use this script for when one wants to manually fuzz a test target with
# Centipede: internal only. Workdir for Centipede is the dir from where this
# script is executed. User is in charge of removing the corpus to start anew.
#
# This script will build Centipede and the fuzz target every time by default.
# If you wish to skip building Centipede (speeds up execution), set
# --build_centipede=false in the command line for subsequent runs.
#
# First argument should be the fuzz target.
# Example usage:
#
# ./third_party/googlefuzztest/rust/e2e_tests/run_with_centipede.sh \
#   //third_party/googlefuzztest/rust/e2e_tests/testdata:fuzztest_main \
#   --fuzz=find_rarer_bug_fuzz_test --fuzz_for=10s

source gbash.sh || exit

DEFINE_string artifact_dir "/tmp" "Build artifacts will be stored here."
DEFINE_string fuzz_for "" "How much time to run the fuzz test for"
DEFINE_string fuzz --required "" "The name of the fuzz test to run"
DEFINE_bool build_centipede true "If false, will not build Centipede."

gbash::init_google "$@"
set -- "${GBASH_ARGV[@]}"

readonly FUZZ_TARGET="${1}"
readonly CENTIPEDE_TARGET="//third_party/googlefuzztest/centipede/google:centipede_uninstrumented"

readonly SYMLINK="${FLAGS_artifact_dir%/}/blaze-"
readonly CENTIPEDE_SYMLINK="${SYMLINK}centipede-"
readonly TARGET_SYMLINK="${SYMLINK}target-"
readonly CENTIPEDE_PATH="${CENTIPEDE_SYMLINK}bin/third_party/googlefuzztest/centipede/google/centipede_uninstrumented"

get_fuzz_target_binary_path() {
  # Remove leading double slashes.
  local FUZZ_TARGET_PATH="${FUZZ_TARGET##//}"
  # Replace last colon with a slash.
  echo "${TARGET_SYMLINK}bin/${FUZZ_TARGET_PATH%:*}/${FUZZ_TARGET_PATH##*:}"
}

build_all() {

  if (( FLAGS_build_centipede )); then
    # BUILD Centipede.
    bazel build -c opt --symlink_prefix="${CENTIPEDE_SYMLINK}" \
      "${CENTIPEDE_TARGET}"
  fi

  # TODO: b/437896409 - Use a dedicated config for Rust FuzzTest.
  # BUILD the fuzz target.
  bazel build --symlink_prefix="${TARGET_SYMLINK}" "${FUZZ_TARGET}" \
    --config=rust-cov --config=asan

}

main() {

  build_all

  declare -a centipede_flags=(
    --binary="$(get_fuzz_target_binary_path)" \
    --persistent_mode=0 --fork_server=0 --populate_binary_info=0 \
    --test_name="${FLAGS_fuzz}" \
  )

  if [[ -n "${FLAGS_fuzz_for}" ]]; then
    centipede_flags+=(--stop_after="${FLAGS_fuzz_for}")
  fi

 "${CENTIPEDE_PATH}" "${centipede_flags[@]}"
}

main
