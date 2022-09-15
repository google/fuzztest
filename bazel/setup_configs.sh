# Script for generating fuzztest.bazelrc.

echo "### DO NOT EDIT. Generated file.
#
# To regenerate, run the following from your project's workspace:
#
#  bazel run @com_google_fuzztest//bazel:setup_configs > fuzztest.bazelrc
#
# And don't forget to add the following to your project's .bazelrc:
#
#  try-import %workspace%/fuzztest.bazelrc
#

### FuzzTest build configuration.
#
# Use with: --config=fuzztest

# Link with Address Sanitizer (ASAN).
build:fuzztest --linkopt=-fsanitize=address

# Link statically.
build:fuzztest --dynamic_mode=off

# Standard define for \"ifdef-ing\" any fuzz test specific code.
build:fuzztest --copt=-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

# In fuzz tests, we want to catch assertion violations even in optimized builds.
build:fuzztest --copt=-UNDEBUG

# We rely on the following flag instead of the compiler provided
# __has_feature(address_sanitizer) to know that we have an ASAN build even in
# the uninstrumented runtime.
build:fuzztest --copt=-DADDRESS_SANITIZER
"

REPO_NAME="${1}"
# When used in the fuzztest repo itself.
if [ ${REPO_NAME} == "@" ]; then
  FUZZTEST_FILTER="//fuzztest:"
# When used in client repo.
elif [ ${REPO_NAME} == "@com_google_fuzztest" ]; then
  FUZZTEST_FILTER="fuzztest/.*"
else
  echo "Unexpected repo name: ${REPO_NAME}"
  exit 1
fi

echo "
# We apply coverage tracking and ASAN instrumentation to everything but the
# FuzzTest framework itself (including GoogleTest and GoogleMock).
build:fuzztest --per_file_copt=+//,-${FUZZTEST_FILTER},-googletest/.*,-googlemock/.*@-fsanitize=address,-fsanitize-coverage=inline-8bit-counters,-fsanitize-coverage=trace-cmp
"
