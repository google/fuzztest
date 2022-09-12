# The `FUZZ_TEST` Macro

Fuzz tests are instantiated with the
FUZZ_TEST
macro. Here's an example:

```c++
void CallingMyApiNeverCrashes(int x, const std::string& s) {
  // Exercise MyApi() with different inputs trying to trigger a crash, e.g.,
  // by invalidating assertions in the code or by causing undefined behaviour.
  bool result = MyApi(x, s);
  ASSERT_TRUE(result);  // The test itself can have assertions too.
}
FUZZ_TEST(MyApiTestSuite, CallingMyApiNeverCrashes)
  .WithDomains(/*x:*/fuzztest::InRange(0,10),
               /*s:*/fuzztest::Arbitrary<std::string>())
  .WithSeeds({{5, "Foo"}, {10, "Bar"}});
```

## The property function

The most important part of the above example is the `CallingMyApiNeverCrashes`
function, which we call the "property function". Fuzz tests are parameterized
unit tests, also called *property-based tests*. The tested property is captured
by a function with some parameters. The test will run this function with many
different argument values. We call this function the "property function",
because the name typically represent the tested property, for example
`CallingMyApiNeverCrashes` in the example above.

The `FUZZ_TEST` macro makes `CallingMyApiNeverCrashes` function an actual fuzz
test. Note that `CallingMyApiNeverCrashes` is both the name of our property
function and the test as well. The first parameter of the macro is the name of
the test suite, and the second is the name of the test (similarly to
[GoogleTest's](https://google.github.io/googletest/)
`TEST()` macro). The test suite `MyApiTestSuite` can contain multiple
`FUZZ_TEST`-s and regular unit `TEST`-s as well. The property function can have
one or more of parameters.

Important things to note about the property function:

*   The function will be run with many different inputs in the same process,
    trying to trigger a crash (assertion failure).
*   The return value should be `void`, as we only care about invalidating
    assertions and triggering undefined behavior.
*   The function should not `exit()` on any input, because that will terminate
    the test execution.
*   Ideally, it should be deterministic (same input arguments should trigger the
    same execution). Non-determinism can make fuzzing inefficient.
*   Ideally, it should not use any global state (only depend on input
    parameters).
*   It may use threads, but threads should be joined in the function.
*   It's better to write more smaller functions (and `FUZZ_TEST`s) than one big
    one. The simpler the function, the easier it is for the tool to cover it and
    find bugs.

The fuzz test macro can specify two additional aspects of the property
function's parameters. Both of them are optional:

*   the *input domains* of the parameters (default is "arbitrary value", when
    not specified), and
*   the *initial seed* values for the parameters (default is a "random value",
    when not specified).

As opposed to
[value-parameterized tests](https://google.github.io/googletest/advanced.html#value-parameterized-tests),
the parameters in property-based tests are not assigned to a set of concrete
values, but to an abstract input domain. The input domain of each parameter of
the property function can be assigned using the `.WithDomains()` clause. An
input domain is an abstraction representing a typed set of values. In the
example above, we specify that the input domain of the first parameter is *"any
integer between 0 and 10"* (closed interval), while the input domain of the
second parameter is *"an arbitrary string"*. If we don't explicitly specify
domains, for a parameter of type `T`, the `fuzztest::Arbitrary<T>()` domain will
be used.

Some initial seed values can also be provided using the `.WithSeeds()` clause.
Initial seed values are concrete input examples that the test deterministically
runs and uses as a basis to create other examples from. In the above example, we
make sure that we run `CallingMyApiNeverCrashes(5, "Foo")`. Providing seed
examples is rarely necessary, it is only useful in cases when we want to make
sure the fuzzer covers some specific case.

Note: If you want to specify domains and seeds, the domain has to be specified
first.

## Input Domains

Input domains are the central concept in FuzzTest. The input domain
specifies the coverage of the property-based testing inputs. The most commonly
used domain is `Arbitrary<T>()`, which represent all possible values of type
`T`. This is also the "default" input domain. This means that when we want use
`Arbitrary<T>()` for every parameter of our property function, for example:

```c++
FUZZ_TEST(MyApiTestSuite, CallingMyApiNeverCrashes)
  .WithDomains(/*x:*/fuzztest::Arbitrary<int>(),
               /*s:*/fuzztest::Arbitrary<std::string>());
```

then the input domain assignment using `.WithDomains()` can be omitted
completely:

```c++
FUZZ_TEST(MyApiTestSuite, CallingMyApiNeverCrashes);
```

See the [Domains Reference](domains-reference.md) for the descriptions of the
various built-in domains and also how you can build your own domains.

## Initial Seeds

A corpus of initial input examples, called "seeds", can be specified via the
`FUZZ_TEST` macro using the `.WithSeeds(...)` function. For example:

```
void CallingMyApiNeverCrashes(int a, const std::string& b) {
...
}
FUZZ_TEST(MyApiTestSuite, CallingMyApiNeverCrashes)
  .WithSeeds({{10, "ABC"}, {15, "DEF"}});
```

where the seeds are of type `std::tuple<Args...>`, `Args...` being the argument
types passed to the property function.

If unspecified, the initial seeds will be randomly generated.

### Loading seed inputs from a directory

You can also provide a checked-in corpus of seeds using
`fuzztest::ReadFilesFromDirectory`, which supports loading
strings. For example:

```
static constexpr absl::string_view kMyCorpusPath = "path/to/my_corpus";

void CallingMyApiNeverCrashes(const std::string& input) {
...
}

FUZZ_TEST(MyApiTestSuite, CallingMyApiNeverCrashes)
    .WithSeeds(fuzztest::ReadFilesFromDirectory(
        absl::StrCat(std::getenv("TEST_SRCDIR"), kMyCorpusPath)));
```

NOTE: You can't use functions like `file::GetTextProto(...)` because the code in
`WithSeeds(...)` runs prior to `InitGoogle`.
