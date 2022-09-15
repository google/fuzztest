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
-   Enumeration types: `enum`, `enum class` (TBD: b/183016365).
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
-   Protocol buffer types: `MyProtoMessage`, etc.

Composite or container types, like `std::optional<T>` or `std::vector<T>`, are
supported as long as the inner types are. For example,
`Arbitrary<std::vector<T1>>()` is implemented, if `Arbitrary<T1>()` is
implemented. The inner elements will be created and mutated via the
`Arbitrary<T1>` domain. For example, the `Arbitrary<std::tuple<int,
std::string>>()` or the `Arbitrary<std::variant<int, std::string>>()` domain
will use `Arbitrary<int>()` and `Arbitrary<std::string>()` as sub-domains.

User defined structs must support aggregate initialization
(https://en.cppreference.com/w/cpp/language/aggregate_initialization), must have
only public members and no more than 32 fields.

Recall that `Arbitrary` is the default input domain, which means that you can
fuzz a function like below without a `.WithDomains()` clause:

```c++
void MyProperty(const absl::flat_hash_map<uint32, MyProtoMessage>& m,
                const absl::optional<std::string>& s) {
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
-   `AlphaNumericChar()` is alias for `OneOf(AlpaChar(), NumericChar())`.
-   `PrintableAsciiChar()` represents any printable character
    (`InRange<char>(32, 126)`).
-   `AsciiChar()` represents any ASCII character (`InRange<char>(0, 127)`).

### String Domains

You can use the following basic string domains:

-   `String()` is an alias for `Arbitrary<std::string>()`.
-   `AsciiString()` represents strings of ASCII characters.
-   `PrintableAsciiString()` represents printable strings.

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

### `ElementOf` Domains

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
e.g.: `OneOf(MagicNumber(), Arbitrary<uint32>())`. TODO reference combinations

Or it can also be used for a
[regular value-parameterized unit tests](https://google.github.io/googletest/advanced.html#value-parameterized-tests):

```c++
void WorksWithAnyPig(const std::string& pig) {
  EXPECT_TRUE(IsLittle(pig));
}
FUZZ_TEST(IsLittlePigTest, WorksWithAnyPig).WithDomains(AnyLittlePig());
```

### `BitFlagCombinationOf` Domains

The `BitFlagCombinationOf` domain takes a list of binary flags and yields a
random combination of them made through bitwise operations (`&`, `^`, etc.).
Consider we have the following bitflag values:

```c++
enum Options {
  kFirst  = 1 << 0,
  kSecond = 1 << 1,
  kThird  = 1 << 2,
};
```

The domain `BitFlagCombinationOf({kFirst, kThird})` will include `{0, kFirst,
kThird, kFirst | kThird}`.

### Protocol Buffer Domains

You can use the `Arbitrary<T>()` domain with any proto message type or bare
proto enum, e.g.:

```c++
void DoingStuffDoesNotCrashWithAnyProto(const ProtoA& msg_a, const ProtoB msg_b) {
  DoStuff(msg_a, msg_b);
}
FUZZ_TEST(MySuite, DoingStuffDoesNotCrashWithAnyProto);

void DoingStuffDoesNotCrashWithEnumValue(Proto::Enum e) {
  switch(e) {
    case Proto::ENUM_ABC:
      // etc...
  }
}
FUZZ_TEST(MySuite, DoingStuffDoesNotCrashWithEnumValue);
```

By default, all fields will use `Arbitrary<U>()` for their values. The
exceptions are:

*   `string` fields which will guarantee UTF8 values.
*   `enum` fields will select only valid labels.

#### Customizing Individual Fields

**Setting the domain of an *optional* field:** You can customize the subdomains
used on individual optional fields by calling `With<Type>Field` method like so:

```c++
FUZZ_TEST(MySuite, DoingStuffDoesNotCrashWithCustomProto).
  WithDomains(Arbitrary<MyProto>()
      .WithInt32Field("int", InRange(1, 10))
      .WithStringField("string", ElementOf<std::string>("op1", "op2"))
      .WithEnumField("enum", ElementOf<int>({Field1, Field2}))
      .WithProtobufField("subproto", Arbitrary<SubProtobuf>()));
```

The inner domain is as follows:

*   For `int32`, `int64`, `uint32`, `uint64`, `bool`, `float`, `double`, and
    `string` fields the inner domain can be any `Domain<T>` of C++ type
    `int32_t`, `int64_t`, `uint32_t`, `uint64_t`, `bool`, `float`, `double`, and
    `std::string` respectively.
*   For `enum` fields the inner domain is a `Domain<int>`. Note that values that
    are not valid enums would be stored in the unknown fields set if the field
    is a closed enum. Open enums would accept any value. The default domain for
    enum fields only chooses between valid labels.
*   For `message` fields the inner domain is a
    `Domain<std::unique_ptr<Message>>`. The domain returned by
    `Arbitrary<MyProto>()` qualifies. Note that even though it uses
    `unique_ptr`, a null value is not allowed and will trigger undefined
    behavior or a runtime assertion of some kind.

The field domains are indexed by field name and will be verified at startup. A
mismatch between the field names and the inner domains will cause a runtime
failure.

IMPORTANT: Note that *optional* fields are not always set by the fuzzer.

**Making an optional field always or never set:** If you want to make sure an
optional field is always set, you can use `With<Type>FieldAlswaysSet()`.
Similarly, if you want an optional field to be always left unset, you can use
`With<Type>FieldUnset()`. For example:

```c++
FUZZ_TEST(MySuite, DoingStuffDoesNotCrashWithCustomProto).
  WithDomains(Arbitrary<MyProto>()
      // Optional field "foo" is always set to a value in [1, 10].
      .WithInt32FieldAlwaysSet("foo", InRange(1, 10))
      // Optional field "bar" is always set to an Arbitrary<T> value.
      .WithInt32FieldAlwaysSet("bar")
      // Optional field "baz" is always left unset.
      .WithStringFieldUnset("baz")
  );
```

**Setting the domain of non-optional fields:** For *required* fields, use
`With<Type>FieldAlswaysSet` and for *repeated* fields use
`WithRepeated<Type>Field`:

```c++
FUZZ_TEST(MySuite, DoingStuffDoesNotCrashWithCustomProto).
  WithDomains(Arbitrary<MyProto>()
      .WithProtobufFieldAlwaysSet("required_int", InRange(0, 10))
      .WithRepeatedProtobufField("repeated_subproto", VectorOf(Arbitrary<SubProtobuf>()).WithSize(2)));
```

For *repeated* fields the domain is of the form `Domain<std::vector<Type>>`.

#### Customizing a Subset of Fields

You can customize the domain for a subset of fields, for example all fields with
message type `Date`, or all fields with "amount" in the field's name.

IMPORTANT: Note that customization options can conflict each other. In case of
conflicts the latter customization always overrides the former.

**Customizing Multiple Fields With Same Type:** You can set the domain for a
subset of fields with the same type using `With<Type>Fields`. By default this
applies to all fields of Type. You can also provide a filter function to select
a subset of fields. Consider the `Moving` proto:

```proto

message Address{
  optional string line1 = 1;
  optional string line2 = 2;
  optional string city = 3;
  optional State state = 4;
  optional int32 zipcode = 5;
}

message Moving{
  optional Address from_address = 1;
  optional Address to_address = 2;
  optional google.protobuf.Timestamp start_ts = 3;
  optional google.protobuf.Timestamp deadline_ts = 4;
  optional google.protobuf.Timestamp finish_ts = 5;
  optional int32 customer_id = 6;
  optional int32 distance = 7;
  optional int32 cost_estimate = 8;
  optional int32 balance = 9;
}
```

Most integer fields should be positive and there are multiple
`Timestamp`/`zipcode` fields which require special domains:

```c++

bool IsZipCode(const FieldDescriptor* field) {
  return field->name() == "zipcode";
}
bool IsTimestamp(const FieldDescriptor* field){
  return field->message_type()->full_name() == "google.protobuf.Timestamp";
}
FUZZ_TEST(MySuite, DoingStuffDoesNotCrashWithCustomProto)
    .WithDomains(Arbitrary<Moving>()
    // All int fields should be positive
    .WithInt32Fields(Positive<int>())
    // except balance field which can be negative
    .WihtInt32Field("balance", Arbitrary<int>())
    // and except all zipcode fields which should have 5 digits
    .WithInt32Fields(IsZipcode, InRange(10000, 99999))
    // All Timestamp fields should have "nanos" field unset.
    .WithProtobufFields(IsTimestamp, Arbitrary<Timestamp>().WithInt32FieldUnset("nanos")));
```

Notice that these filters apply recursively to nested protos as well.

**Customizing Multiple Optional Fields:** Recall that optional fields are not
always set, you can customize the nullness for a subset of optional fields using
`WithOptionalFieldsAlwaysSet`, `WithOptionalFieldsUnset`, and filters:

```c++
bool IsProtoType(const FieldDescriptor* field){
  return field->cpp_type() == FieldDescriptor::CPPTYPE_MESSAGE;
}
FUZZ_TEST(MySuite, DoingStuffDoesNotCrashWithCustomProto).
  WithDomains(Arbitrary<MyProto>()
      // Always set optional fields
      .WithOptionalFieldsAlwaysSet()
      // except fields that contain nested protos.
      .WithOptionalFieldsUnset(IsProtoType)
      // and except "foo" field. We override the nullness by using the
      // WithInt32Filed (instead of WithInt32FieldAlwaysSet()), which will
      // enable the fuzzer make this field both set and unset.
      .WithInt32Field("foo", Arbitrary<int>())
  );
```

**Customizing Multiple Repeated Fields:** You can customize the size for all or
a subset of repeated fields using `WithRepeatedFieldsMinSize`,
`WithRepeatedFieldsMaxSize`, and filters:

```c++
bool IsCitizenship(const FieldDescriptor* field){
  return return field->name() == "citizenship";
}
FUZZ_TEST(MySuite, DoingStuffDoesNotCrashWithCustomProto).
  WithDomains(Arbitrary<MyProto>()
    // Repeated fields should have size in range 1-10
    .WithRepeatedFieldsMinSize(1)
    .WithRepeatedFieldsMaxSize(10)
    // except citizenship fields which can size at most 2.
    .WithRepeatedFieldsMaxSize(IsCitizenship, 2)
    // and except "additional_info" field which can be empty or arbitrary large
    .WithInt32Field("additional_info", VectorOf(String()).WithMinSize(0))
  );
```

Notice that `WithOptionalFieldsAlwaysSet`, `WithOptionalFieldsUnset`,
`WithRepeatedFieldsMinSize`, and `WithRepeatedFieldsMaxSize` work recursively
and applies to subprotos as well, but calling `WithOptionalFieldsAlwaysSet()`
and `WithRepeatedFieldsMinSizeByDefault(X)` with `X > 0` on recursively defined
protos causes a failure.

## What Domains Should You Use for View Types?

If your property function takes "view types", such as `std::string_view` or
`std::span<T>`, you have multiple options.

For a `std::string_view` parameter you can use `std::string` domains, such as
`Arbitrary<std::string>()` or `InRegexp("[ab]+")`. The `string`-s created by the
domain get implicitly converted to `string_view`-s. Alternatively, you can use
`Arbitrary<std::string_view>()` which creates `string_view`-s in the first
place, automatically backed by `string` values. This means that in regular
value-parameterized unit tests,
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
StringOf(OneOf(InRange('a', 'z'), ElementOf('.', '!', '?')))
```

(See [OneOf](#oneof-combinator) combinator and [ElementOf](#elementof-domain)
domain.)

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

The size of any container domain can be customized using the `WithSize()`,
`WithMinSize()` and `WithMaxSize()` setters.

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

### OneOf Combinators

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

### Map-ing Domains

Often the best way to define a domain is using a mapping function. The `Map()`
domain combinator takes a mapping function and an arbitrary number of domains.
It uses the inner domains to generate values which are mapped using the passed
function. For example:

```c++
auto AnyDurationString() {
  auto any_int = Arbitrary<int>();
  auto suffixes = ElementOf<std::string>("s", "m", "h");
  return Map(
    [](int i, const std::string& suffix) { return std::to_string(i) + suffix; },
    any_int, suffixes);
}
```

### Filter-ing Domains

The `Filter` domain takes a domain and a predicate and returns a new domain that
uses the predicate to filter the generated values.

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
