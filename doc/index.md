# FuzzTest

## What is FuzzTest?

FuzzTest is a C++ testing framework for writing fuzz tests and/or
property-based tests.

It is our latest fuzz testing technology and the successor of previously used
fuzzing tools, such as [libFuzzer](https://llvm.org/docs/LibFuzzer.html).

It allows you to write more powerful fuzz tests, and more easily, than with
previously used
[fuzz targets](https://llvm.org/docs/LibFuzzer.html#fuzz-target).

It is integrated with
[GoogleTest](https://google.github.io/googletest/),
so you can write fuzz test just like you write regular unit tests.

It is a first-of-its-kind tool that bridges the gap between fuzzing and
property-based testing, as it is both:

1.  a testing framework with a rich [API](domains-reference.md) (akin to
    property-based testing libraries), and
2.  a coverage-guided fuzzing engine (akin to
    [AFL](https://github.com/google/AFL) or
    [libFuzzer](https://llvm.org/docs/LibFuzzer.html)).

## Who is it for?

FuzzTest is for *everyone* who writes C++ code. (Currently, only C++ is
supported.)

You can write fuzz tests using GoogleTest as easily as you write unit tests.
Simply use the [`FUZZ_TEST`](fuzz-test-macro.md) macro like you would use the
TEST macro for unit tests.

To get a high level idea what you can do with fuzz tests, take a look at the
[Overview](overview.md)
page.

## How do I use it?

To get started, read the
[Overview](overview.md) and [Quickstart with Bazel](quickstart-bazel.md).

Continue by read the rest of the documentation, including the:

*   [Use Cases](use-cases.md)
*   [FUZZ_TEST Macro Reference](fuzz-test-macro.md)
*   [Domains Reference](domains-reference.md)

## Who uses it?

Numerous teams uses FuzzTest and say great things about it.
