# FuzzTest Domain Reference

[TOC]

This document describes the available input domains, and how you can create your
own domains, within FuzzTest. The first section lists the set of existing
primary domains. A second section lists "combinators" which allow the mixing of
two or more primary domains.

Note: Note that all APIs described below are in the `fuzztest::` namespace.

## Built-In Domains

The following domains are built into FuzzTest as primary domains which you can
use out of the box.

### Arbitrary Domains

The `Arbitrary<T>()` domain is implemented for all native C++ types and for
protocol buffers. Specifically, for the following types:

-   Boolean type: `bool`.
-   Character types: `char`, `signed char`, `unsigned char`.
-   Integral types: `short`, `int`, `unsigned`, `int8_t`, `uint32_t`, `long
    long`, etc.
-   Floating types: `float`, `double`, etc.
-   Simple user defined structs.
-   Tuple types: `std::pair<T1,T2>`, `std::tuple<T,...>`.
-   Smart pointers: `std::unique_ptr<T>`, `std::shared_ptr<T>`.
-   Optional types: `std::optional<T>`.
-   Variant types: `std::variant<T,...>`.
-   String types: `std::string`, etc.
-   String view type: `std::string_view`.
-   Sequence container types: `std::vector<T>`, `std::array<T>`,
    `std::deque<T>`, `std::list<T>`, etc.
-   Unordered associative container types: `std::unordered_set`,
    `absl::flat_hash_set`, `absl::node_hash_set`, `std::unordered_map`,
    `absl::flat_hash_map`, `absl::node_hash_map`, etc.
-   Ordered associative container types: `std::set<K>`, `std::map<K,T>`,
    `std::multiset<K>`, `std::multimap<K,T>`, etc.
-   Uniform Random Bit Generator types: `absl::BitGenRef`
-   Protocol buffer types: `MyProtoMessage`, etc.
-   [Abseil time library types](https://abseil.io/docs/cpp/guides/time):
    `absl::Duration`, `absl::Time`.

Composite or container types, like `std::optional<T>` or `std::vector<T>`, are
supported as long as the inner types are. For example,
`Arbitrary<std::vector<T1>>()` is implemented, if `Arbitrary<T1>()` is
implemented. The inner elements will be created and mutated via the
`Arbitrary<T1>` domain. For example, the `Arbitrary<std::tuple<int,
std::string>>()` or the `Arbitrary<std::variant<int, std::string>>()` domain
will use `Arbitrary<int>()` and `Arbitrary<std::string>()` as sub-domains.

User defined structs must support
[aggregate initialization](https://en.cppreference.com/w/cpp/language/aggregate_initialization),
must have only public members, and no more than 80 fields. In addition, they
cannot have C-style array members (e.g., `int[5]`).

TIP: If your struct doesn't satisfy the requirements for `Arbitrary`, you can
construct a domain for it using `Map`, `ReversibleMap`, or `FlatMap`.

Recall that `Arbitrary` is the default input domain, which means that you can
fuzz a function like below without a `.WithDomains()` clause:

```c++
void MyProperty(const absl::flat_hash_map<uint32, MyProtoMessage>& m,
                const std::optional<std::string>& s) {
  //...
}
FUZZ_TEST(MySuite, MyProperty);
```

Under the hood, FuzzTest implements each domain as a custom object mutator.
These mutators, combined with the underlying coverage-guided fuzzing algorithm,
iteratively find values that increase the coverage of the code under test.
Beyond that, it also tries "special" values of the given domain. E.g., for
arbitrary integer domains, it will try values like `0`, `1`, and
`std::numeric_limits<T>::max()`. For floating point domains will try values like
`0`, `-0`, `NaN`, and `std::numeric_limits<T>::infinity()`. For container
domains it will try empty, small and large containers, and so on.

### Numerical Domains

Other than `Arbitrary<int>()`, `Arbitrary<float>()`, etc., we have the following
more "restricted" numerical domains:

-   `InRange(min, max)` represents any value between [`min`, `max`], closed
    interval. E.g., an arbitrary probability value could be represented with
    `InRange(0.0, 1.0)`.
-   `NonZero<T>()` is like `Arbitrary<T>()` without the zero value.
-   `Positive<T>()` represents numbers greater than zero.
-   `NonNegative<T>()` represents zero and numbers greater than zero.
-   `Negative<T>()` represents numbers less than zero.
-   `NonPositive<T>` represents zero and numbers less than zero.
-   `Finite<T>` represent floating points numbers that are neither infinity nor
    NaN.

For instance, if your test function has a precondition that the input has to be
positive, you can write your FUZZ_TEST like this:

```c++
void MyProperty(int x) {
  ASSERT(x > 0);
  // ...
}
FUZZ_TEST(MySuite, MyProperty).WithDomains(Positive<int>());
```

### Character Domains

Other than `Arbitrary<char>()`, we have the following more specific character
domains:

-   `InRange(min, max)` can be applied to characters as well, e.g.,
    `InRange('a', 'z')`.
-   `NonZeroChar()` represents any char except `'\0'`.
-   `NumericChar()` is alias for `InRange('0', '9')`.
-   `LowerChar()` is alias for `InRange('a', 'z')`.
-   `UpperChar()` is alias for `InRange('A', 'Z')`.
-   `AlphaChar()` is alias for `OneOf(LowerChar(), UpperChar())`.
-   `AlphaNumericChar()` is alias for `OneOf(AlphaChar(), NumericChar())`.
-   `PrintableAsciiChar()` represents any printable character
    (`InRange<char>(32, 126)`).
-   `AsciiChar()` represents any ASCII character (`InRange<char>(0, 127)`).

### String Domains

You can use the following basic string domains:

-   `String()` is an alias for `Arbitrary<std::string>()`.
-   `AsciiString()` represents strings of ASCII characters.
-   `PrintableAsciiString()` represents printable strings.
-   `Utf8String()` represents valid UTF-8 strings.

You also define your string domains with custom character domains using the
[StringOf()](#string-combinator) domain combinator.

### `InRegexp` Domains

You can also use regular expressions to define a string domain. The `InRegexp`
domain represents strings that are sentences of a given regular expression. You
can use any regular expression syntax
[accepted by RE2](https://github.com/google/re2/wiki/Syntax). For example:

```c++
auto DateLikeString() {
  return InRegexp("[0-9]{4}-[0-9]{2}-[0-9]{2}");
}

auto EmailLikeString() {
  return InRegexp("[a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-z]{2,6}*");
}
```

This is useful for testing APIs that required specially formatted strings like
email addresses, phone numbers, URLs, etc. Here is an example test for a date
parser:

```c++
// Tests with values matching the regexp below (like `08/29/5434`) that the
// parser always return true. Note that the regexp doesn't handle leap years.
static void ParseFirstDateInStringAlwaysSucceedsForDates(
    const std::string& date_str) {
  StringDateParser date_parser(false);
  SimpleDate output;
  EXPECT_TRUE(date_parser.ParseFirstDateInString(
      date_str, i18n_identifiers::language_code::ENGLISH_US(), &output));
}
FUZZ_TEST(EnglishLocaleTest, ParseFirstDateInStringAlwaysSucceedsForDates)
    .WithDomains(fuzztest::InRegexp(
        "^(0[1-9]|1[012])/(0[1-9]|[12][0-9])/[1-9][0-9]{3}$"));
```

### `ElementOf` Domains {#element-of}

We can also define a domain by explicitly enumerating the set of values in it.
You can do this with the `ElementOf` domain, that can be instantiated with a
vector of constant values of some type, e.g.:

```c++
auto AnyLittlePig() {
  return ElementOf<std::string>({"Fifer Pig", "Fiddler Pig", "Practical Pig"});
}

auto MagicNumber() {
  return ElementOf({0xDEADBEEF, 0xBADDCAFE, 0xFEEDFACE});
}
```

The type can be anything, `enum`s too:

```c++
enum Status { kYes, kNo, kMaybe };

auto AnyStatus() {
  return ElementOf<Status>({kYes, kNo, kMaybe});
}
```

The `ElementOf` domain is often used in combination with other domains, for
instance to provide some concrete examples while fuzzing with arbitrary inputs,
e.g.: `OneOf(MagicNumber(), Arbitrary<uint32>())`.

Or it can also be used for a
[regular value-parameterized unit tests](https://google.github.io/googletest/advanced.html#value-parameterized-tests):

```c++
void WorksWithAnyPig(const std::string& pig) {
  EXPECT_TRUE(IsLittle(pig));
}
FUZZ_TEST(IsLittlePigTest, WorksWithAnyPig).WithDomains(AnyLittlePig());
```

Note: `ElementOf` supports [initial seeds](fuzz-test-macro.md#initial-seeds)
only for arithmetic types, enums, strings (`std::string` and
`std::string_view`), and Abseil time library types (`absl::Duration` and
`absl::Time`).

`.WithDomains()` can be omitted:

```c++
void UnescapeNeverCrashes(std::string_view s) { Unescape(s); }
FUZZ_TEST(UnescapeTest, UnescapeNeverCrashes);
```

If you have a `std::span` parameter, you can use a `std::vector` domain, for
example:

```c++
void MyProperty(std::span<int> ints) { ... }
FUZZ_TEST(MySuite, MyProperty).WithDomains(Arbitrary<std::vector<int>>());
```

TODO(b/200074418): More native support for view types.

## Domain Combinators

Domain combinators let you create more complex domains from simpler ones.

### String Combinator

The `StringOf(character_domain)` domain combinator function lets you specify the
domain of the characters in `std::string`. For instance, to represent strings
that are composed only of specific characters, you can use

```c++
StringOf(OneOf(InRange('a', 'z'), ElementOf({'.', '!', '?'})))
```

(See [OneOf](#oneof) combinator and [ElementOf](#element-of) domain.)

Another example is the `AsciiString()`, whose implementation is
`StringOf(AsciiChar())`.

### Container Combinators

You can specify the domain of the *elements* in a container using container
combinators. `ContainerOf<T>(elements_domain)` is the generic container
combinator, which you can use like this:

```c++
auto VectorOfNumbersBetweenOneAndSix() {
  auto one_to_six = InRange(1, 6);
  return ContainerOf<std::vector<int>>(one_to_six);
}
```

This domain represents any vector whose elements are numbers between 1 and 6.

The previous example can be simplified by dropping `<int>` after `std:vector`,
as this can be inferred automatically:

```c++
auto VectorOfNumbersBetweenOneAndSix() {
return ContainerOf<std::vector>(InRange(1, 6));
}
```

In particular, if the container type `T` is a class template (e.g.
`std::vector`) whose first template parameter is the type of the values stored
in the container, and whose other template parameters, if any, are optional,
then all the template parameters of `T` may be omitted, in which case
`ContainerOf` will use the `value_type` of the `elements_domain` as the first
template parameter for `T`.

`ContainerOf` is rarely used directly however, as there are more ergonomic
shorthands available shown below.

#### Shorthands

We provide shorthand aliases for the most common container combinator types.
E.g., the above example can be written simply as

```c++
VectorOf(InRange(1, 6))
```

The following shorthand aliases are available:

-   `VectorOf(inner)` is alias for `ContainerOf<std::vector<T>>(inner)`.

-   `DequeOf(inner)` is alias for `ContainerOf<std::deque<T>>(inner)`.

-   `ListOf(inner)` is alias for `ContainerOf<std::list<T>>(inner)`.

-   `SetOf(inner)` is alias for `ContainerOf<std::set<T>>(inner)`.

-   `MapOf(key_domain, value_domain)` is alias for
    `ContainerOf<std::map<K,T>>(PairOf(key_domain, value_domain))`.

-   `UnorderedSetOf(inner)` is alias for
    `ContainerOf<std::unordered_set<T>>(inner)`.

-   `UnorderedMapOf(key_domain, value_domain)` is alias for
    `ContainerOf<std::unordered_map<K,T>>(PairOf(key_domain, value_domain))`.

-   `ArrayOf(inner1, ..., innerN)` creates a domain for `std::array<T, N>`,
    where `N` is the number of inner domains, and where `T` is the value type of
    every one of the inner domains (i.e. they're all the same).

-   `ArrayOf<N>(inner)` is alias for `ArrayOf(inner, ..., inner)`, where `N`
    copies of `inner` are passed to `ArrayOf`.

### Custom Container Size

You can customize the size of any container domain with the following setters:

*   `WithSize(S)`: sets container size to exactly `S`.
*   `WithMinSize(S)`: sets minimum container size to `S`.
*   `WithMaxSize(S)`: sets maximum container size to `S`.
*   `WithSoftMaxSize(S)`: sets the maximum size to S and disables maximum size
    validation. The domain accepts containers with more than S elements as valid
    (e.g., when provided as seeds), but it only shrinks them during mutation.

If `WithSoftMaxSize(N)` and `WithMaxSize(M)` are both used, the latter call
overrides the former.

For instance, to represent arbitrary integer vectors of size 42, we can use:

```c++
Arbitrary<std::vector<int>>().WithSize(42)
```

This works with container combinators as well, e.g.:

```c++
ContainerOf<std::vector<int>>(InRange(0,10)).WithMinSize(2).WithMaxSize(3)
```

or

```c++
VectorOf(InRange(0,10)).WithMinSize(2).WithMaxSize(3)
```

#### NonEmpty Containers

To represent any non-empty container you can use `NonEmpty()`, e.g.,

```c++
NonEmpty(Arbitrary<std::vector<int>>())
```

or

```c++
NonEmpty(VectorOf(String()))
```

The `NonEmpty(domain)` is shorthand for `domain.WithMinSize(1)`.

### Unique Elements Containers

Sometimes we need a vector with all unique elements. We can use the
`UniqueElementsContainerOf<T>()` combinator to get one.

```c++
UniqueElementsContainerOf<std::vector<int>>(Arbitrary<int>())
```

or using the shorthand:

```c++
UniqueElementsVectorOf(Arbitrary<int>())
```

### Aggregate Combinators

Just like with containers, we often need to specify the inner domains of
[aggregate data types](https://en.cppreference.com/w/cpp/language/aggregate_initialization).
We can do this with various aggregate combinator functions listed in this
section.

#### StructOf

The StructOf combinator function lets you define the domain of each field of a
user-defined struct.

```c++
struct Thing {
  int id;
  std::string name;
};

auto AnyThing() {
  return StructOf<Thing>(InRange(0, 10),
                          Arbitrary<std::string>());
}
```

#### ConstructorOf

The `ConstructorOf<T>()` combinator lets you define a domain for a class T by
specifying the domains for T's constructor parameters. For example:

```c++
auto AnyAbslStatus() {
  return ConstructorOf<absl::Status>(
    /*status_code:*/ConstructorOf<absl::StatusCode>(InRange(0, 18)),
    /*message:*/Arbitrary<std::string>());
}
```

Note: Domains defined using `ConstructorOf` don't support
[initial seeds](fuzz-test-macro.md#initial-seeds).

#### PairOf

The `PairOf` domain represents `std::pair<T1,T2>` of the provided inner domains.
For example, the domain:

```c++
PairOf(InRange(0, 10), Arbitrary<std::string>());
```

provides values of type `std::pair<int, std::string>`, where the first element
is always between 1 and 10, and the second element is an arbitrary string.

#### TupleOf

The `TupleOf` domain combinator works just like the above `PairOf`. For example,
the domain:

```c++
auto MyTupleDomain() {
  return TupleOf(InRange(0, 10),
                 InRange(0, 10),
                 Arbitrary<std::string>());
}
```

represents values of type `std::tuple<int, int, std::string>`, with the
specified sub-domains.

#### VariantOf

The `VariantOf` domain combinator lets you define the domain for `variant`
types. For instance, the example domain below represents values of type
`std::variant<int, double, std::string>`, with the provided sub-domains.

```c++
auto MyVariantDomain() {
  return VariantOf(InRange(0, 10),
                   Arbitrary<double>(),
                   Arbitrary<std::string>());
}

```

By default, `VariantOf` represents `std::variant` types, but it can also be used
to represent other variant types:

```c++
auto MyAbslVariantDomain() {
  return VariantOf<absl::variant<int, double>>(InRange(0, 10),
                                               Arbitrary<double>(),
```

#### OptionalOf

The `OptionalOf` domain combinator lets you specify the sub-domain for value
type `T` for an `optional<T>` type. For instance, the domain:

```c++
OptionalOf(InRange(0, 10));
```

represents values of type `std::optional<int>` of integers between 0 and 10.
Note that this domain includes `nullopt` as well. By default, the domain will
represent `std::optional`, but other optional types can be used as well:

```c++
OptionalOf<absl::optional<int>>(InRange(0, 10))
```

To restrict the nullness of the domain, you can use `NullOpt` and `NonNull`:

```c++
// Generates only null values.
NullOpt<int>()
// Generates optional<int> values that always contain an int value
// (i.e., it's never nullopt).
NonNull(OptionalOf(InRange(0, 10)))
```

#### `SmartPointerOf`, `UniquePtrOf`, `SharedPtrOf`

The `SmartPointerOf` domain combinator lets you specify a smart pointer `T` and
a subdomain to create its contents. For instance, the domain:

```c++
SmartPointerOf<std::unique_ptr<int>>(InRange(0, 10));
```

represents values of type `std::unique_ptr<int>` of integers between 0 and 10.
Note that this domain includes `nullptr` as well. Shortcuts for
`std::unique_ptr` and `std::shared_ptr` exist in the form:

```c++
UniquePtrOf(int_domain) == SmartPointerOf<std::unique_ptr<int>>(int_domain)
SharedPtrOf(int_domain) == SmartPointerOf<std::shared_ptr<int>>(int_domain)
```

### OneOf

With the `OneOf` combinator we can merge multiple domains of the same type. For
example:

```c++
auto PositiveOrMinusOne() {
  return OneOf(Just(-1), Positive<int>());
}
```

The `Just` domain combinator simply wraps a constant into a domain, which is
necessary in this case, as OneOf only takes domains as arguments.

Note that the list of domains must be known at compile time; unlike `ElementOf`,
you can't use a vector of domains.

### OverlapOf

With the `OverlapOf` combinator, we can use multiple domains to constrain a
single type. The generated values satisfy all of the provided domains. For
example:

```c++
auto ConstrainedNonZero() {
  return OverlapOf(NonZero<int64_t>(), InRange<int64_t>(-355, 355));
}
```

`ConstrainedNonZero()` produces integers between -355 and 355, but never 0.
This may be useful in cases where 0 is silently interpreted as a sentinel value
(e.g., "not set").

### Map {#map}

Often the best way to define a domain is using a mapping function. The `Map()`
domain combinator takes a mapping function and an input domain for each of its
parameters. It uses the input domains to generate values which are mapped using
the passed function. For example:

```c++
auto AnyDurationString() {
  auto any_int = Arbitrary<int>();
  auto suffixes = ElementOf<std::string>("s", "m", "h");
  return Map(
    [](int i, const std::string& suffix) { return std::to_string(i) + suffix; },
    any_int, suffixes);
}
```

Note: Domains defined using `Map()` don't support
[initial seeds](fuzz-test-macro.md#initial-seeds). If you need a
[seeded domain](#seeded-domains)—a domain skewed toward certain values—consider
seeding the input domains passed to `Map()`. Otherwise, if you need full support
for seeds, consider using [`ReversibleMap()`](#reversible-map).

Note: If your return type is an
[aggregate type](https://en.cppreference.com/w/cpp/language/aggregate_initialization)
with a nested C-style array, you may get a compile-time error about a mismatch
between the number of elements the type binds to and the number of names
provided (e.g., `binds to 2 elements, but 3 names were provided`). A workaround
is to define a [custom value printer](#custom-value-printers) for the type.

### ReversibleMap {#reversible-map}

The `ReversibleMap()` domain combinator is similar to `Map()`: it takes a
mapping function and input domains for its parameters, and it defines a domain
of values generated by applying the mapping function on the values from the
input domains. Additionally, `ReversibleMap()` also takes an inverse mapping
function that maps the values from the mapped domain back into the input
domains. With this, `ReversibleMap()` is able to support
[initial seeds](fuzz-test-macro.md#initial-seeds). For example:

```c++
auto ArbitraryComplex() {
  return ReversibleMap(
      // The mapping function maps a pair of doubles to std::complex.
      [](double real, double imag) {
        return std::complex<double>{real, imag};
      },
      // The inverse mapping function maps std::complex back to a pair
      // (std::tuple) of doubles. The return value is additionally wrapped in
      // std::optional.
      [](std::complex<double> z) {
        return std::optional{std::tuple{z.real(), z.imag()}};
      },
      Arbitrary<double>(), Arbitrary<double>());
}

void MyComplexProperty(std::complex<double> z);
FUZZ_TEST(MyFuzzTest, MyComplexProperty)
  .WithDomains(ArbitraryComplex())
  .WithSeeds({std::complex<double>{0.0, 1.0}});
```

The return type of the inverse mapping function should be
`std::optional<std::tuple<T...>>`, where `T...` are the input types of the
mapping function. Note that `std::tuple` is necessary even if the mapping
function has a single parameter.

The mapping function doesn't necessarily need to be one-to-one. If it isn't
and it maps several input domain tuples to the same value `y`, then the inverse
mapping function can map `y` back to any of these input domain tuples. For
example:

```c++
ReversibleMap([](int a, int b) { return std::max(a, b); },
              [](int c) {
                return std::optional{std::tuple{c, c}};
              },
              Arbitrary<int>(), Arbitrary<int>())
```

In this example, the mapping function maps `(0, 2)`, `(1, 2)`, and `(2, 2)` to
`2`, and the inverse mapping function maps `2` back to `(2, 2)`.

IMPORTANT: The mapping function `f` and the inverse mapping function `g` must
satisfy the following property. If `g` maps a value `y` to a tuple whose
components are in the respective input domains, then `f` must map this tuple to
`y`; that is `f(g(y)) == y`.

To ensure this property, the inverse mapping function may need to return
`std::nullopt`. For example:

```c++
ReversibleMap(
    [](int a, int b) {
      return a > b ? std::pair{a, b} : std::pair{b, a};
    },
    [](std::pair<int, int> p) {
      auto [a, b] = p;
      return a >= b ? std::optional{std::tuple{a, b}} : std::nullopt;
    },
    Arbitrary<int>(), Arbitrary<int>())
```

In this example, the mapping function (call it `f`) always returns a a pair `(a,
b)` such that `a >= b`. Thus, when `a < b`, the inverse mapping function (call
it `g`) must return `std::nullopt` because there is no possible value it could
return so that `f(g(std::pair{a, b})) == std::pair{a, b}`.

Note: The [note for `Map`](#map) about aggregate types with nested C-style
arrays also applies to `ReversibleMap`.

### FlatMap

Sometimes we need to fuzz parameters that are dependent on each other. Think of
a property function that takes a string, and valid index into that string. This
can be achieved using the `FlatMap()` combinator, which takes a domain *factory*
function, and an input domain for each of its parameters. I.e. `FlatMap` is like
`Map`, except it takes a function which returns a `Domain`. This allows us to
use the output of some domains (e.g., the string) as the input for another
domain (e.g., the string and a valid index).

```c++
Domain<pair<string,size_t>> AnyStringAndValidIndex() {
  auto valid_index_paired_with_string = [](const string& s) {
    return PairOf(Just(s), InRange(0, s.size() - 1));
  };
  return FlatMap(valid_index_paired_with_string, Arbitrary<string>());
}
```

Here's an example domain for a vector of *equal sized strings*:

```c++
auto AnyVectorOfFixedLengthStrings(int size) {
  return VectorOf(Arbitrary<std::string>().WithSize(size));
}
auto AnyVectorOfEqualSizedStrings() {
  return FlatMap(AnyVectorOfFixedLengthStrings, /*size=*/InRange(0, 10));
}
```

If `AnyVectorOfFixedLengthStrings()` had been passed to `Map()`, it would have
generated a `Domain<Domain<std::vector<std::string>>>`. `FlatMap()` "flattens"
this to a `Domain<std::vector<std::string>>`. Thus the name FlatMap.

Another example is a pair of numbers `(a, b)`, where `b > 2 * a`:

```c++
Domain<pair<int,int>> AnyPairOfOrderedNumbers() {
  auto a_and_b = [](int a) {
    return PairOf(Just(a), InRange(2 * a + 1, MAX_INT));
  };
  return FlatMap(a_and_b, Arbitrary<int>());
}
```

Note: Domains defined using `FlatMap()` don't support
[initial seeds](fuzz-test-macro.md#initial-seeds). If you need a
[seeded domain](#seeded-domains)—a domain skewed toward certain values—consider
seeding the input domains passed to `FlatMap()`.

Note: The [note for `Map`](#map) about aggregate types with nested C-style
arrays also applies to `FlatMap`.

### Filter

The `Filter` domain combinator takes a domain and a predicate and returns a new
domain that uses the predicate to filter the generated values.

```c++
auto NonZero() {
  return Filter([](int x) { return x != 0; }, Arbitrary<int>());
}
```

Filtering through a domain is usually more efficient over filtering in the
property function, thus it is preferred.

Important: Make sure that your filtering condition is not too restrictive.
Filtering simply drops values provided by the inner domain that don't match the
condition. So filters with very low yield would lead to ineffective fuzzing.
Therefore too restrictive filter functions will trigger an abort in the
framework.

Unless you want filter just a few specific values (e.g., the NonZero example
above), consider if you can defined the domain with `Map()`-ing instead. For
instance, instead of:

```c++ {.bad}
auto EvenNumber() {
  return Filter([](int i) { return i % 2 == 0; }, Arbitrary<int>());
}
```

you should use:

```c++ {.good}
auto EvenNumber() {
  return Map([](int i) { return 2 * i; },
             // Ensure we don't try to produce a value that causes integer
             // overflow; what happens next would be undefined behavior.
             InRange(std::numeric_limits<int>::min() / 2,
                     std::numeric_limits<int>::max() / 2));
}
```

This leads to more efficient fuzzing, as no values will be dropped and no cycles
will be wasted.

### Recursive Domains

**WARNING**: Recursion limit for recursive domains is not implemented yet
. If the probability of recursion is high in the domain, the initial input
generation might "blow up", leading to resource exhaustion. Note that this is
not an issue in case of protobuf domains (when there's recursion in the protobuf
definition), because recursion is avoided during the initial input generation
and only happens during mutating the inputs.

Recursive data structures need recursive domains. We can use the `DomainBuilder`
to build such domains. Here are some examples:

```c++
// Example 1: Self recursion.
struct Tree {
  int value;
  std::vector<Tree> children;
};

auto ArbitraryTree(){
  DomainBuilder builder;
  builder.Set<Tree>(
    "tree", StructOf<Tree>(InRange(0, 10), ContainerOf<std::vector<Tree>>(
                                                 builder.Get<Tree>("tree"))));
  return std::move(builder).Finalize<Tree>("tree");
}

// Example 2: Loop recursion.
struct RedTree;

struct BlackTree {
  int value;
  std::vector<RedTree> children;
};

struct RedTree {
  int value;
  std::vector<BlackTree> children;
};

auto ArbitraryRedBlackTree(){
  DomainBuilder builder;
  builder.Set<RedTree>(
    "redtree", StructOf<RedTree>(InRange(0, 10),
                                 ContainerOf<std::vector<BlackTree>>(
                                     builder.Get<BlackTree>("blacktree"))));
  builder.Set<BlackTree>(
    "blacktree", StructOf<BlackTree>(InRange(0, 10),
                                     ContainerOf<std::vector<RedTree>>(
                                         builder.Get<RedTree>("redtree"))));

  return std::move(builder).Finalize<RedTree>("redtree");
}
```

The builder maintains a set of sub-domains that comprise the domain. Every
domain in the builder is referenced by a name. The builder provides three
methods: `Get`, `Set`, and `Finalize`. `Get` returns a domain of the specified
type even if it hasn't been created. `Set` sets the final domain type of the
domain.

When you have finished, call `Finalize` to get the domain ready for use. After
calling `Finalize`, the builder will be invalidated.

## Seeded domains {#seeded-domains}

When asked to produce an initial value, a domain typically returns a random
value, sometimes with a strong bias toward special cases. For example, initial
values for `Arbitrary<int>()` are biased toward values such as 0, 1, the
maximum, etc., and an unconstrained protocol buffer domain initially produces an
empty protocol buffer.

You can skew most built-in domains toward your own special values by specifying
*initial seeds*. Use the `.WithSeeds()` function to do this. For example:

```c++
auto HttpResponseCode() {
  return Arbitrary<int>().WithSeeds({200, 404, 500});
}
```

In addition to the default special-case integers, `HttpResponseCode()` also
produces `200`, `404`, and `500` with high probability.

Note that the [`FUZZ_TEST` macro](fuzz-test-macro.md) also has a `.WithSeeds()`
function, which serves for specifying
[initial seeds](fuzz-test-macro.md#initial-seeds) at the fuzz test
instantiation. FuzzTest calls the test's property function on those seeds when
it starts executing the test. In contrast, the domain seeds are not directly
passed to the property function. Instead, they are picked with high probability
when the domain needs to produce an initial value. The difference can sometimes
be subtle, like in the following example:

```c++
void TestOne(std::string) {}
FUZZ_TEST(MySuite, TestOne)
  .WithDomains(Arbitrary<std::string>())
  .WithSeeds({"foo", "bar"});

void TestTwo(std::string) {}
FUZZ_TEST(MySuite, TestTwo)
  .WithDomains(Arbitrary<std::string>().WithSeeds({"foo", "bar"}));
```

In `TestOne`, FuzzTest initially calls `TestOne("foo")` and `TestOne("bar")`,
and it continues fuzzing `TestOne` with arbitrary strings. In `TestTwo`,
FuzzTest immediately starts fuzzing `TestTwo`, but this time with strings coming
from a seeded domain: occasionally, as FuzzTest asks the domain for an initial
value, the domain is likely to produce `foo` and `bar`. (In a more typical
iteration, FuzzTest asks the domain to mutate an existing value, and then the
initial seeds don't play a role.)

Seeded domains occur more commonly as part of complex domains constructed using
domain combinators. In complex domains, seeded domains can appear at any level.
For example:

```c++
auto BiasedPairs() {
  return PairOf(InRange(0, 100).WithSeeds({7}), Arbitrary<std::string>)
      .WithSeeds({{42, "Foo"}});
}
```

The domain `BiasedPairs()` is likely to produce pairs where the first component
is `7`, as well as the specific pair `(42, "Foo")`.

Finally, just like with the
[`FUZZ_TEST` macro](fuzz-test-macro.md#seed-providers), seed initialization for
a domain can be delayed using a seed provider. For a domain over a type `T`, a
seed provider is any invocable (e.g., a lambda, function pointer, callable
object, etc.) that doesn't take inputs and returns `std::vector<T>`. For
example:

```c++
Arbitrary<int>().WithSeeds([]() -> std::vector<int> { return {7, 42}; });
```

This is useful for avoiding static initialization issues: FuzzTest invokes the
seed provider the first time it needs to get an initial value from the domain.

Note: Some domains don't support seeds. `ElementOf` and `Just` support seeds
only for certain types (see [`ElementOf`](#element-of)). Complex domains
constructed using combinators `ConstructorOf`, `Map`, and `FlatMap` don't
support seeds.

## Customizing Value Printers {#custom-value-printers}

FuzzTest provides a mechanism to display the values that cause a test to fail.
By default, it knows how to print standard C++ types, including
[aggregate types](https://en.cppreference.com/w/cpp/language/aggregate_initialization),
but you can extend this system to support your own custom types. This is
especially useful for making test failure reports clear and actionable. There
are two ways FuzzTest prints values, and you can customize the output for each:

-   Human-readable mode: This mode is designed to be easily read and understood
    by a developer. The goal is clarity, not necessarily compilable code.
-   Source code mode: This mode generates a string that is a valid C++
    expression. This is used in the auto-generated regression tests to recreate
    the exact value that caused the failure. This mode is purely best-effort.

### Customizing the human-readable printer

For aggregate types, FuzzTest already provides a default printer that performs
field-level printing, but without field names. For example, if you have:

```c++
struct MyObject {
  int id;
  std::string name;
};
```

The default output for `MyObject{1, "Alice"}` will be `MyObject{1, "Alice"}`.

To customize the output, the simplest and most recommended way is to implement
`AbslStringify`. This hooks into Abseil's string formatting library, which
FuzzTest uses internally. For example:

```c++
struct MyObject {
  int id;
  std::string name;

  template <typename Sink>
  friend void AbslStringify(Sink& sink, const MyObject& obj) {
    absl::Format(&sink, "MyObject{.id = %d, .name = \"%s\"}", obj.id, obj.name);
  }
};
```

Now the output for `MyObject{1, "Alice"}` will be
`MyObject{.id = 1, .name = "Alice"}`.

WARNING: If your aggregate type contains a nested C-style array, the default
field-type printing may yield a compile-time error (see the
[note for `Map`](#map)). In this case, you should define a custom printer as
a workaround.

### Customizing the source code printer

To provide a custom source code representation (which is used in regression
tests), you can implement the `FuzzTestPrintSourceCode` function for your type.
For example:

```c++
class MyObject {
 public:
  static MyObject Make(int id, std::string name) {
    return MyObject{id, std::move(name)};
  }

  template <typename Sink>
  friend void FuzzTestPrintSourceCode(Sink& sink, const MyObject& v) {
    absl::Format(&sink, "MyObject::Make(%d, \"%s\")", v.id_, v.name_);
  }

 private:
  MyObject(int id, std::string name) : id_{id}, name_{std::move(name)} {}

  int id_ = 0;
  std::string name_;
};
```

If you define only one of `AbslStringify` and `FuzzTestPrintSourceCode`,
FuzzTest will use the defined function for both the human-readable and the
source-code mode. If you define both, FuzzTest will use `AbslStringify` for the
human-readable mode, and `FuzzTestPrintSourceCode` for the source-code mode.

NOTE: FuzzTest does not validate the output. You are responsible for ensuring
that in the source-code mode, the function prints a valid C++ expression that
correctly recreates the original value.

NOTE: FuzzTest uses ADL resolution to find `AbslStringify` and
`FuzzTestPrintSourceCode`. These functions should generally be declared either
at the same place as the printed struct/class or in the same translation unit as
the fuzz test.
