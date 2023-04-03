# FuzzTest

## What is FuzzTest?

FuzzTest is a C++ testing framework for writing and executing *fuzz tests*,
which are property-based tests executed using coverage-guided fuzzing under the
hood. Fuzz tests are like regular unit tests, but more generic and more
powerful. Instead of saying: "for this specific input, we expect this specific
output", we can say: "for these types of input, we expect this generic property
to be true". For example:

```c++
void MyApiAlwaysSucceedsOnPositiveIntegers(int i) {
  bool success = MyApi(i);
  EXPECT_TRUE(success);
}
FUZZ_TEST(MyApiTest, MyApiAlwaysSucceedsOnPositiveIntegers)
    .WithDomains(/*i:*/fuzztest::Positive<int>());
```

It is our latest fuzz testing technology and the successor of previously used
fuzzing tools, such as [libFuzzer](https://llvm.org/docs/LibFuzzer.html). It
allows you to write powerful fuzz tests more easily than with previously used
[fuzz targets](https://llvm.org/docs/LibFuzzer.html#fuzz-target). You can use it
together with [GoogleTest](https://google.github.io/googletest/), or other unit
testing frameworks, allowing you to write fuzz test side by side with regular
unit tests, and just as easily.

It is a first-of-its-kind tool that bridges the gap between fuzzing and
property-based testing, as it is both:

1.  a testing framework with a rich [API](doc/domains-reference.md) (akin to
    property-based testing libraries), and
2.  a coverage-guided fuzzing engine (akin to
    [AFL](https://github.com/google/AFL) or
    [libFuzzer](https://llvm.org/docs/LibFuzzer.html)).

## Who is it for?

FuzzTest is for *everyone* who writes C++ code. (Currently, only C++ is
supported.) Fuzz testing is a proven testing technique that has found
[tens of thousands of bugs](https://github.com/google/oss-fuzz#trophies). With
the FuzzTest framework writing these tests becomes a breeze. Because fuzz tests
are more generic, they are more powerful than regular unit tests. They can find
tricky edge cases automatically for us, edge cases that most likely we would
never think of.

You can write fuzz tests as easily as you write unit tests using GoogleTest for
example. Simply use the [`FUZZ_TEST`](doc/fuzz-test-macro.md) macro like you
would use GoogleTest's `TEST` macro.

## Who uses it?

At Google, FuzzTest is widely used and software engineers love it. It has
replaced the old style of writing
[fuzz targets](https://llvm.org/docs/LibFuzzer.html#fuzz-target).

## How do I use it?

To get started, read the [Quickstart with Bazel](doc/quickstart-bazel.md) or
[Quickstart with CMake](doc/quickstart-cmake.md), then take a look at the
[Overview](doc/overview.md) and the [Codelab](doc/tutorial.md).

Once you have a high level understanding about fuzz tests, consider reading the
rest of the documentation, including the:

*   [Use Cases](doc/use-cases.md)
*   [FUZZ_TEST Macro Reference](doc/fuzz-test-macro.md)
*   [Domains Reference](doc/domains-reference.md)

## I need help!

If you have a question or encounter a bug, please file an
[issue on GitHub](https://github.com/google/fuzztest/issues).
