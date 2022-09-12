# FuzzTest Overview

Consider a typical unit test for a function that parses the leading digits of a
string into an integer:

```c++
TEST(ParseLeadingDigitsTest, ParsesIntCorrectly) {
  std::string input = "42IsTheAnswer";
  std::optional<int> output = ParseLeadingDigits(input);
  EXPECT_THAT(output, Optional(Eq(42)));
}
```

This single input/output example is great, but what if there is some tricky edge
case with some other input? Wouldn’t it be great to have a test that is not
specific to 42?

With FuzzTest, you can write tests that generalize to a wider set of
inputs:

```c++
void ParsesIntCorrectly(int number, const std::string& suffix) {
  std::string input = absl::StrCat(number, suffix);
  std::optional<int> output = ParseLeadingDigits(input);
  EXPECT_THAT(output, Optional(Eq(number)));
}
FUZZ_TEST(ParseLeadingDigitsTest, ParsesIntCorrectly)
  .WithDomains(/*number=*/Arbitrary<int>(), /*suffix=*/InRegexp("[^0-9].*"));
```

In the fuzz test version of the above test, ParsesIntCorrectly runs
ParseLeadingDigits with many different inputs, specified by abstract input
domains. The test has parameters (`number` and `suffix`), and it verifies that
the output matches the input parameter number, as shown below:

FuzzTest will run a test with many different parameter values from the
specified input domains and find tricky edge cases that invalidate your
assertions.

Writing fuzz tests requires you to shift focus from providing interesting
specific inputs to specifying properties that must hold for all inputs. If you
can identify properties that generalize to all inputs, write a fuzz test and let
FuzzTest find the tricky edge cases for you. This sort of testing is
commonly known as "property-based testing".

The most typical property to check is that your code has no undefined behavior
(e.g., buffer overflows, use-after-frees, integer overflows, uninitialized
memory, etc). You can rely on the implicit assertions of sanitizers
to test for such undefined behavior:

```c++
void HasNoUndefinedBehavior(const std::string& input) {
  ParseLeadingDigits(input);
}
FUZZ_TEST(ParseLeadingDigitsTest, HasNoUndefinedBehavior); // Uses Arbitrary<T> as input domain for each parameter by default.
```
