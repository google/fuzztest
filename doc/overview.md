# FuzzTest Overview

Consider a typical unit test for a function that parses the leading digits of a
string into an integer:

```c++
TEST(ParseLeadingDigitsTest, ParsesIntCorrectly) {
  const std::string input = "42IsTheAnswer";
  const std::optional<int> output = ParseLeadingDigits(input);
  EXPECT_THAT(output, Optional(Eq(42)));
}
```

This single input/output example is great, but what if there is some tricky edge
case with some other input? Wouldn’t it be great to have a test that is not
specific to `42`?

With FuzzTest, you can write tests that generalize to a wider set of inputs:

```c++
void ParsesIntCorrectly(int number, const std::string& suffix) {
  const std::string input = absl::StrCat(number, suffix);
  const std::optional<int> output = ParseLeadingDigits(input);
  EXPECT_THAT(output, Optional(Eq(number)));
}
FUZZ_TEST(ParseLeadingDigitsTest, ParsesIntCorrectly)
  .WithDomains(/*number=*/Arbitrary<int>(), /*suffix=*/InRegexp("^\D.*"));
```

In the fuzz test version of the above test, `ParsesIntCorrectly` runs
`ParseLeadingDigits` with many different inputs, specified by abstract input
domains. The test has parameters (`number` and `suffix`), and it verifies that
the output matches the input parameter number. We call `ParsesIntCorrectly` the
*property function*, which we instantiate with the `FUZZ_TEST` macro.

FuzzTest will run a test with many different parameter values from the specified
input domains and find tricky edge cases that invalidate your assertions.

Writing fuzz tests requires you to shift focus from providing interesting
specific inputs to specifying `EXPECT`-ations (properties) that must hold for a
given set of inputs. This doesn't mean that you always need to write explicit
`ASSERT`/`EXPECT` statements in the property function (the test body). You might
simply check that the `ASSERT`-ions in your code under test don't get
invalidated with any inputs. If you can identify properties that generalize to
all or a set of inputs, your can write additional assertions too and let
FuzzTest find the tricky edge cases for you. This sort of testing is commonly
known as "property-based testing".

The most typical property to check is that your code has no undefined behavior
(e.g., buffer overflows, use-after-frees, integer overflows, uninitialized
memory, etc). This doesn't need any explicit assertions either, because you can
rely on the implicit assertions of sanitizers
(https://clang.llvm.org/docs/AddressSanitizer.html)
to test for such undefined behavior:

```c++
void HasNoUndefinedBehavior(const std::string& input) {
  ParseLeadingDigits(input);
}
FUZZ_TEST(ParseLeadingDigitsTest, HasNoUndefinedBehavior);  // Uses Arbitrary<T> as input domain for each parameter by default.
```
