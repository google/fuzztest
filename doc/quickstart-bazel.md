# Quickstart with Bazel

This tutorial describes how to set up your development environment with Bazel as
the build system, and how to get a simple fuzz test up and running. We recommend
this tutorial if you're new to FuzzTest or if you need a quick refresher. For a
more extensive showcase of the FuzzTest framework, consider doing the
[Codelab](tutorial.md).

## Prerequisites

To use FuzzTest, you'll need:

*   A Linux-based operating system
*   [Clang](https://clang.llvm.org/)
*   [Bazel](https://bazel.build/)

## Set up a Bazel workspace

First, create a directory where your project will reside:

```sh
$ mkdir -p my_workspace && cd my_workspace
```

In this directory, create a file named `WORKSPACE` to define a
[Bazel workspace](https://bazel.build/concepts/build-ref#workspace). The file
will configure FuzzTest along with its transitive dependencies as Bazel external
dependencies:

```
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

################################################################################
# Direct dependencies
################################################################################

# To use the latest version of FuzzTest, update this regularly to the latest
# commit in the main branch: https://github.com/google/fuzztest/commits/main
FUZZTEST_COMMIT = "62cf00c7341eb05d128d0a3cbce79ac31dbda032"

http_archive(
    name = "com_google_fuzztest",
    strip_prefix = "fuzztest-" + FUZZTEST_COMMIT,
    url = "https://github.com/google/fuzztest/archive/" + FUZZTEST_COMMIT + ".zip",
)

http_archive(
    name = "com_google_googletest",
    sha256 = "81964fe578e9bd7c94dfdb09c8e4d6e6759e19967e397dbea48d1c10e45d0df2",
    strip_prefix = "googletest-release-1.12.1",
    url = "https://github.com/google/googletest/archive/refs/tags/release-1.12.1.tar.gz",
)

################################################################################
# Transitive dependencies
################################################################################

# Required by com_google_fuzztest.
http_archive(
    name = "com_googlesource_code_re2",
    sha256 = "f89c61410a072e5cbcf8c27e3a778da7d6fd2f2b5b1445cd4f4508bee946ab0f",
    strip_prefix = "re2-2022-06-01",
    url = "https://github.com/google/re2/archive/refs/tags/2022-06-01.tar.gz",
)

# Required by com_google_fuzztest.
http_archive(
    name = "com_google_absl",
    sha256 = "3ea49a7d97421b88a8c48a0de16c16048e17725c7ec0f1d3ea2683a2a75adc21",
    strip_prefix = "abseil-cpp-20230125.0",
    url = "https://github.com/abseil/abseil-cpp/archive/refs/tags/20230125.0.tar.gz",
)

# Required by com_google_absl.
http_archive(
    name = "bazel_skylib",
    sha256 = "f7be3474d42aae265405a592bb7da8e171919d74c16f082a5457840f06054728",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.2.1/bazel-skylib-1.2.1.tar.gz",
        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.2.1/bazel-skylib-1.2.1.tar.gz",
    ],
)
```

NOTE: We recommend the users to "live at head," that is, to often update the
`com_google_fuzztest` repository to the latest commit from the main branch.

NOTE: It is possible to use FuzzTest without GoogleTest, and thus without
depending on `com_google_googletest`, but this is beyond the scope of this
tutorial.

Next, create a [Bazel configuration file](https://bazel.build/run/bazelrc) named
`.bazelrc` to configure the build flags:

```
# Force the use of Clang for all builds. FuzzTest relies on Clang for sanitizer
# coverage (https://clang.llvm.org/docs/SanitizerCoverage.html).
build --action_env=CC=clang
build --action_env=CXX=clang++

# Use the C++17 standard.
build --cxxopt=-std=c++17

# Use the builtin crc32 for fast integer hashing.
build --copt=-mcrc32

# Show everything when running tests.
test --test_output=streamed

# To create this file, please run:
#
#  bazel run @com_google_fuzztest//bazel:setup_configs > fuzztest.bazelrc
#
try-import %workspace%/fuzztest.bazelrc
```

As suggested by the comments, generate a file named `fuzztest.bazelrc` with
additional build configurations. We generate the file using a script from the
FuzzTest repo to make sure it contains the correct and recent settings:

```sh
$ bazel run @com_google_fuzztest//bazel:setup_configs > fuzztest.bazelrc
```

## Create and run a fuzz test

With the Bazel workspace set up, you can start using FuzzTest. Let's create a
trivial example to make sure everything runs correctly.

Create a file named `first_fuzz_test.cc` in the directory `my_workspace` with
the following contents:

```c++
#include "fuzztest/fuzztest.h"
#include "gtest/gtest.h"

TEST(MyTestSuite, OnePlustTwoIsTwoPlusOne) {
  EXPECT_EQ(1 + 2, 2 + 1);
}

void IntegerAdditionCommutes(int a, int b) {
  EXPECT_EQ(a + b, b + a);
}
FUZZ_TEST(MyTestSuite, IntegerAdditionCommutes);
```

The file contains two tests in the test suite named `MyTestSuite`. The first one
is a unit test named `OnePlustTwoIsTwoPlusOne` asserting that integer addition
commutes for two specific values.

The second test is a fuzz test that captures the commutative property of integer
addition more generally. The test consists of a property function with a
suggestive name `IntegerAdditionCommutes`, and the test registration using the
macro `FUZZ_TEST`. The property function asserts the commutative property for
two generic integer parameters.

To build and run the tests, create a file named `BUILD` with the following
contents:

```
cc_test(
    name = "first_fuzz_test",
    srcs = ["first_fuzz_test.cc"],
    deps = [
        "@com_google_fuzztest//fuzztest",
        "@com_google_fuzztest//fuzztest:fuzztest_gtest_main",
        "@com_google_googletest//:gtest"
    ],
)
```

This defines a C++ test binary and links it with the FuzzTest and GoogleTest
libraries, as well as the version of the default GoogleTest main that supports
FuzzTest.

There are two ways to run the tests: in the unit test mode and in the fuzzing
mode. The unit test mode runs both test for a short time without sanitizer and
coverage instrumentation:

```
$ bazel test :first_fuzz_test

WARNING: Streamed test output requested. All tests will be run locally, without sharding, one at a time
INFO: Analyzed target //:first_fuzz_test (71 packages loaded, 1231 targets configured).
INFO: Found 1 test target...
[==========] Running 2 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 2 tests from MyTestSuite
[ RUN      ] MyTestSuite.OnePlustTwoIsTwoPlusOne
[       OK ] MyTestSuite.OnePlustTwoIsTwoPlusOne (0 ms)
[ RUN      ] MyTestSuite.IntegerAdditionCommutes
[       OK ] MyTestSuite.IntegerAdditionCommutes (13 ms)
[----------] 2 tests from MyTestSuite (13 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test suite ran. (13 ms total)
[  PASSED  ] 2 tests.
Target //:first_fuzz_test up-to-date:
  bazel-bin/first_fuzz_test
INFO: Elapsed time: 14.089s, Critical Path: 4.54s
INFO: 488 processes: 262 internal, 226 linux-sandbox.
INFO: Build completed successfully, 488 total actions
//:first_fuzz_test                                                       PASSED in 0.1s

Executed 1 out of 1 test: 1 test passes.
INFO: Build completed successfully, 488 total actions
```

The fuzzing mode runs a single specified fuzz test with sanitizer and coverage
instrumentation. It keeps running the test with different input values until it
finds a crash or it is explicitly terminated by the user:

```
$ bazel run --config=fuzztest :first_fuzz_test -- \
    --fuzz=MyTestSuite.IntegerAdditionCommutes

INFO: Build options --copt, --dynamic_mode, --linkopt, and 1 more have changed, discarding analysis cache.
INFO: Analyzed target //:first_fuzz_test (0 packages loaded, 1231 targets configured).
INFO: Found 1 target...
Target //:first_fuzz_test up-to-date:
  bazel-bin/first_fuzz_test
INFO: Elapsed time: 14.570s, Critical Path: 5.11s
INFO: 161 processes: 4 internal, 157 linux-sandbox.
INFO: Build completed successfully, 161 total actions
INFO: Build completed successfully, 161 total actions
exec ${PAGER:-/usr/bin/less} "$0" || exit 1
Executing tests from //:first_fuzz_test
-----------------------------------------------------------------------------
[.] Sanitizer coverage enabled. Counter map size: 21290, Cmp map size: 262144
Note: Google Test filter = MyTestSuite.IntegerAdditionCommutes
[==========] Running 1 test from 1 test suite.
[----------] Global test environment set-up.
[----------] 1 test from MyTestSuite
[ RUN      ] MyTestSuite.IntegerAdditionCommutes
[*] Corpus size:     1 | Edges covered:    131 | Fuzzing time:    504.798us | Total runs:  1.00e+00 | Runs/secs:     1
[*] Corpus size:     2 | Edges covered:    133 | Fuzzing time:    934.176us | Total runs:  3.00e+00 | Runs/secs:     3
[*] Corpus size:     3 | Edges covered:    134 | Fuzzing time:   2.384383ms | Total runs:  5.30e+01 | Runs/secs:    53
[*] Corpus size:     4 | Edges covered:    137 | Fuzzing time:   2.732274ms | Total runs:  5.40e+01 | Runs/secs:    54
[*] Corpus size:     5 | Edges covered:    137 | Fuzzing time:   7.275553ms | Total runs:  2.48e+02 | Runs/secs:   248
[*] Corpus size:     6 | Edges covered:    137 | Fuzzing time:   21.97155ms | Total runs:  9.12e+02 | Runs/secs:   912
[*] Corpus size:     7 | Edges covered:    137 | Fuzzing time: 166.721522ms | Total runs:  8.49e+03 | Runs/secs:  8491
[*] Corpus size:     8 | Edges covered:    146 | Fuzzing time: 500.398497ms | Total runs:  2.77e+04 | Runs/secs: 27741
[*] Corpus size:     9 | Edges covered:    146 | Fuzzing time: 500.821386ms | Total runs:  2.77e+04 | Runs/secs: 27742
[*] Corpus size:    10 | Edges covered:    147 | Fuzzing time: 2.597553524s | Total runs:  1.75e+05 | Runs/secs: 87476
^C
```

Congratulations! You're now all set for fuzzing with FuzzTest.

## Next steps

*   This tutorial covered the basic setup of the build environment with Bazel.
    To learn more about the FuzzTest framework and how to use it, check out the
    [Codelab](tutorial.md).
*   Explore the rest of the [documentation](./).
