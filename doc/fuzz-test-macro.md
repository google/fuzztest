# The `FUZZ_TEST` macro

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

The three parts of the instantiation that we discuss in more detail are the
following:

*   The *property function* (called `CallingMyApiNeverCrashes` in the example).
*   The *input domains* for the property function's parameters, specified using
    the `.WithDomains()` clause.
*   The *initial seed* values for the parameters, specified using the
    `.WithSeeds()` clause.

The property function is a mandatory part of the instantiation; the input
domains and the seeds are optional. If you want to specify both the input
domains and the seeds, you have to specify the input domains first.

WARNING: The `FUZZ_TEST` macro expands into a global variable definition. Thus,
you should be careful when initializing the input domains or seeds with other
global objects. Never initialize the input domains or seeds with global objects
that are initialized in other compilation units! Doing this may lead to the
[static initialization order fiasco](https://en.cppreference.com/w/cpp/language/siof).
You may use [seed providers](#seed-providers) to delay the initialization of
seeds.

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

## Input domains

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

## Initial seeds {#initial-seeds}

You can use the `.WithSeeds()` clause to provide the initial seed values for the
property function's parameters. The initial seed values are concrete inputs that
FuzzTest deterministically runs and uses as a basis for creating other inputs.
In the above example, the seed `{5, "Foo"}` causes FuzzTest to execute
`CallingMyApiNeverCrashes(5, "Foo")`. In the subsequent runs, FuzzTest may
generate similar values, like `{5, "Foooo"}` or `{10, "Foo"}`, and use them as
inputs to the property function.

Providing seeds is not necessary; if you don't provide them, FuzzTest will
generate them at random. However, in certain cases providing seeds can greatly
improve fuzzing efficiency.

Note: Some domains don't support seeds. `ElementOf` and `Just` support seeds
only for certain types (see [`ElementOf`](domains-reference.md#element-of)).
Complex domains constructed using combinators `ConstructorOf`, `Map`, and
`FlatMap` don't support seeds.

### Delaying seed initialization with a seed provider {#seed-providers}

As noted earlier, fuzz tests are instantiated as global variables, so
initializing seeds from other global objects (especially those coming from other
compilation units) can lead to unexpected consequences or even undefined
behavior. For cases when such initialization cannot be avoided, the
`.WithSeeds()` clause also accepts a *seed provider*—a function that returns a
vector of seeds. FuzzTest will call the seed provider in runtime, thus avoiding
any static initialization issues.

The seed provider can be any invocable (lambda, function pointer, callable
object, etc.) that doesn't take inputs and returns
`std::vector<std::tuple<Args...>>`, where `Args...` are the types of the
property function's parameters. In the example from earlier, we could use the
following seed provider:

```c++
FUZZ_TEST(MyApiTestSuite, CallingMyApiNeverCrashes)
  .WithSeeds([]() -> std::vector<std::tuple<int, std::string>> {
    return {{5, "Foo"}, {10, "Bar"}};
  });
```

If you are using a [test fixture](fixtures.md), the seed provider can also be a
pointer to a member function of the fixture, as in the following example:

```c++
class MyFuzzTest {
 public:
  void CallingMyApiNeverCrashes(int x, const std::string& s);

  // The seed provider can depend on the fixture's state.
  std::vector<std::tuple<int, std::string>> seeds() { return seeds_; }

 private:
  std::vector<std::tuple<int, std::string>> seeds_ = {{5, "Foo"}, {10, "Bar"}};
};

FUZZ_TEST_F(MyFuzzTest, CallingMyApiNeverCrashes)
  // The seed provider can be a pointer to the fixture's member function. Note
  // that the member function can't be const.
  .WithSeeds(&MyFuzzTest::seeds);
```

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

