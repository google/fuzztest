# Quickstart with CMake

This tutorial describes how to set up your development environment with CMake as
the build system, and how to get a simple fuzz test up and running. We recommend
this tutorial if you're new to FuzzTest or if you need a quick refresher.

## Definitions

The library can work in several different modes.

*   Unit test mode (*default*): FUZZ_TESTs are built without coverage
    instrumentation and run with random inputs for short period of time along
    with regular unit TESTs.
*   Fuzzing mode (controlled by `-DFUZZTEST_FUZZING_MODE=on`): FUZZ_TESTs are
    built with coverage instrumentation and run individually and indefinitely or
    for specified amount of time.
*   Compatibility mode (controlled by
    `-DFUZZTEST_COMPATIBILITY_MODE=libfuzzer`): like Fuzzing mode, but an
    external engine is used instead FuzzTest's built in engine. Currently
    [libFuzzer](https://llvm.org/docs/LibFuzzer.html) is supported.

    **Warning:** compatibility mode is experimental and does not guarantee full
    FuzzTest features.

## Overall rules

We provide a default CMake option for unittest mode, the instructions are
straightforward and work like
[googletest](https://google.github.io/googletest/quickstart-cmake.html).

To run in a fuzztest mode, you need to make sure all targets are compiled in a
special way.

*   `-g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -UNDEBUG`
*   `-fsanitize-coverage=inline-8bit-counters -fsanitize-coverage=trace-cmp`
*   `-fsanitize=address -DADDRESS_SANITIZER` (optionally enabling sanitizer)

The FuzzTest framework doesn't need to be built with these flags, only the target project.

For all projects to have correct flags set, use a CMake macro
`fuzztest_setup_fuzzing_flags()`.

For a concrete example, see the root CMakeLists.txt. First, we build framework
without additional flags and then build the rest of translation units with
coverage flags. Otherwise we might get into recursive issues, i.e. fuzztest
framework will be fuzzing itself.

Easiest way to make sure you build everything correctly is to invoke
`add_subdirectory` first in your project on fuzztest.

## Prerequisites

To use FuzzTest, you'll need:

*   A Linux-based operating system.
*   [Clang](https://clang.llvm.org/). GCC is not yet supported. Unittest mode
    mode should work but it's not yet tested.
*   [CMake](https://https://cmake.org/).

## Set up a CMake workspace

First, create a directory where your project will reside:

```sh
$ mkdir first_fuzz_project && cd first_fuzz_project
$ git clone https://github.com/google/fuzztest.git
```

Create a `CMakeLists.txt`.

```
cmake_minimum_required(VERSION 3.19)
project(first_fuzz_project)

# GoogleTest requires at least C++17
set(CMAKE_CXX_STANDARD 17)

add_subdirectory(fuzztest)
```

FuzzTest CMake already handles its dependencies on its own:
[RE2](https://github.com/google/re2),
[Abseil](https://github.com/abseil/abseil-cpp). We highly recommend using
[GoogleTest](https://github.com/google/googletest) as well.

## Create and run a fuzz test

With the CMake workspace set up, you can start using FuzzTest. Let's create a
trivial example to make sure everything runs correctly.

Create a file named `first_fuzz_test.cc` in the directory `first_fuzz` with the
following contents:

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

To build and run the tests, **add** to the file `CMakeLists.txt` the following
content:

```cmake

...

enable_testing()

include(GoogleTest)

add_executable(
  first_fuzz_test
  first_fuzz_test.cc
)

# If you have other dependencies than FuzzTest, link them:
# target_link_libraries(first_fuzz_test PRIVATE other_deps)

link_fuzztest(first_fuzz_test)
gtest_discover_tests(first_fuzz_test)
```

This defines a C++ test binary and links it with the FuzzTest and GoogleTest
libraries, as well as the version of the default GoogleTest main that supports
FuzzTest.

### Unit test mode

There are several ways to run the tests: in the unit test mode and in the
fuzzing mode (see above). The unit test mode runs both test for a short time
without sanitizer and coverage instrumentation:

```
$ mkdir build && cd build
$ CC=clang CXX=clang++ cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebug ..
$ cmake --build .
$ ./first_fuzz_test

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
```

### Fuzzing mode

The fuzzing mode runs a single specified fuzz test with sanitizer and coverage
instrumentation. It keeps running the test with different input values until it
finds a crash or it is explicitly terminated by the user.

Before `add_executable(first_fuzz_test ...)`, add the specified flags:

```cmake
fuzztest_setup_fuzzing_flags()
```

Then run:

```
$ CC=clang CXX=clang++ cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebug \
  -DFUZZTEST_FUZZING_MODE=on ..
$ cmake --build .
$ ./first_fuzz_test --fuzz=MyTestSuite.IntegerAdditionCommutes

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

### Compatibility mode

**Warning:** compatibility mode is experimental and does not guarantee full
FuzzTest features.

```
$ CC=clang CXX=clang++ cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebug \
  -DFUZZTEST_COMPATIBILITY_MODE=libfuzzer ..
$ cmake --build .
$ ./first_fuzz_test --fuzz=MyTestSuite.IntegerAdditionCommutes

Note: Google Test filter = MyTestSuite.IntegerAdditionCommutes
[==========] Running 1 test from 1 test suite.
[----------] Global test environment set-up.
[----------] 1 test from MyTestSuite
[ RUN      ] MyTestSuite.IntegerAdditionCommutes
FUZZTEST_PRNG_SEED=OffQXb8u5_vZtH4-7wgVOLu_HNAhPIbLz7CFF13u3nk
INFO: found LLVMFuzzerCustomMutator (0x55edfe61cac0). Disabling -len_control by default.
INFO: libFuzzer ignores flags that start with '--'
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1109364873
INFO: Loaded 1 modules   (18692 inline 8-bit counters): 18692 [0x55edfe975548, 0x55edfe979e4c), 
INFO: Loaded 1 PC tables (18692 PCs): 18692 [0x55edfe979e50,0x55edfe9c2e90), 
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED cov: 17 ft: 18 corp: 1/1b exec/s: 0 rss: 38Mb
#3	NEW    cov: 104 ft: 108 corp: 2/66b lim: 4096 exec/s: 0 rss: 38Mb L: 65/65 MS: 1 Custom-
#4	NEW    cov: 105 ft: 112 corp: 3/121b lim: 4096 exec/s: 0 rss: 38Mb L: 55/65 MS: 1 Custom-
#5	NEW    cov: 105 ft: 113 corp: 4/196b lim: 4096 exec/s: 0 rss: 38Mb L: 75/75 MS: 1 Custom-
#16	REDUCE cov: 105 ft: 113 corp: 4/195b lim: 4096 exec/s: 0 rss: 38Mb L: 54/75 MS: 1 Custom-
#41	NEW    cov: 105 ft: 114 corp: 5/247b lim: 4096 exec/s: 0 rss: 38Mb L: 52/75 MS: 5 Custom-Custom-Custom-Custom-Custom-
#65	NEW    cov: 106 ft: 115 corp: 6/312b lim: 4096 exec/s: 0 rss: 38Mb L: 65/75 MS: 4 Custom-Custom-Custom-Custom-
#69	NEW    cov: 108 ft: 119 corp: 7/365b lim: 4096 exec/s: 0 rss: 38Mb L: 53/75 MS: 4 Custom-Custom-Custom-Custom-
```

## Next steps

*   This tutorial covered the basic setup of the build environment with CMake.
    To learn more about the FuzzTest framework and how to use it, check out the
    [Codelab](tutorial.md).
*   Explore the rest of the [documentation](./).
