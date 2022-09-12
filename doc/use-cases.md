# FuzzTest Use Cases

## Finding Undefined Behavior with Sanitizers

By far the most typical type of fuzz test is the one that checks for undefined
behavior. These are easy to write as
sanitizers
take care of
the assertions, we just need to exercise the code under test:

```c++
void UnescapeStringNeverCrashes(const std::string& s) {
  UnescapeString(s);
}
FUZZ_TEST(TagUtilsFuzzTests, UnescapeStringNeverCrashes);
```

These tests can find serious security vulnerabilities and other robustness bugs,
such as

-   buffer overflows,
-   use-after-frees,
-   uninitialized memory,
-   memory leaks,
-   division by zero,
-   integer overflows,
-   invalid casts,
-   nullptr dereferences,
-   data races,
-   hangs,
-   infinite recursion,
-   memory exhaustion bugs,
-   algorithmic complexity vulnerabilities,
-   etc.

By default, sanitizers are enabled in fuzzing mode. Whether or not the code
under test has any explicit assertions in it (e.g., `CHECK`/`DCHECK`), the
implicit undefined behavior checks of the sanitizer will always catch these
bugs.

## Find Correctness Bugs using Explicit Assertions

The other main type of fuzz tests is when we check for some correctness
properties as well (on top of undefined behavior). We can do this by either
adding assertions to code under test or to the test itself. The more assertions
you have in your implementation, `CHECK`-ing invariants, pre- and
post-conditions, the more bugs you can catch. You can also assert some higher
level properties in the test itself, in your property function. There are a few
common patterns for such correctness properties that you can use.

### API Invariants

Often the API you’re testing has some correctness invariant. This test, for
example asserts that workflow IDs are always unique, i.e., no two IDs are ever
the same:

```c++
void BuildWorkflowIdTest(WorkflowType type) {
  std::string workflow_id_1 = BuildWorkflowId(type);
  std::string workflow_id_2 = BuildWorkflowId(type);

  EXPECT_THAT(workflow_id_1, ::testing::Ne(workflow_id_2));
  int32_t length = WorkflowType::Type_Name(type.type()).size();
  // length + len("_")=1 + len(str(timestamp_usec))=16 + len("_")=1
  // + len(unique_id)=16 = length + 34
  EXPECT_EQ(length + 34, workflow_id_1.size());
  EXPECT_EQ(length + 34, workflow_id_2.size());
}
FUZZ_TEST(WorkflowUtilFuzzTest, BuildWorkflowIdTest)
    .WithDomains(fuzztest::Arbitrary<WorkflowType>());
```

This one is for a linear algebra library, checking that rotating any 2D vector
won’t change its magnitude:

```c++
void RotationDoesNotChangeMagnitude(Vector2f v, float angle) {
  {
    Vector2f rotated =
        v *
        RotationMatrix<SecondComponentPoints::Down, MatrixOnThe::Right>(angle);
    EXPECT_NEAR(Magnitude<float>(v), Magnitude<float>(rotated), 1E-5);
  }

  {
    Vector2f rotated =
        RotationMatrix<SecondComponentPoints::Down, MatrixOnThe::Left>(angle) *
        v;
    EXPECT_NEAR(Magnitude<float>(v), Magnitude<float>(rotated), 1E-5);
  }
}
FUZZ_TEST(LinearAlgebraTest, RotationDoesNotChangeMagnitude)
    .WithDomains(Vector2fDomain(), InRange(-2 * M_PI, 2 * M_PI));
```

### Differential Fuzzing with an Oracle

If you have two implementations of the same thing, you can check that they both
return the same value for any input. For example, this proto library tests its
`Equals` method against `util::MessageDifferencer::Equals`:

```c++
void EqualsConsistentWithMessageDifferencerProto3(
    const testdata::TestProto3Type& m1, const testdata::TestProto3Type& m2) {
  EXPECT_EQ(testdata::Equals(m1, m2), util::MessageDifferencer::Equals(m1, m2));
}
FUZZ_TEST(CppEqualsGeneratorTest, EqualsConsistentWithMessageDifferencerProto3);
```

The "oracle" implementation is often just a simpler version of the real
implementation.

### Roundtrip Fuzzing

Certain pairs of operations, like encoding/decoding, compression/decompression,
or serialize/parse, are symmetrical. For these we can test that for any input,
if we decode an encoded value, we get back the original. For instance, this
proto library prints then parses back a message to ensure that the result is the
same as the original message.

```c++
void PrintThenParseEqualsOriginalProto3(
    const proto3_unittest::TestAllTypes& m) {
  TextFormat::Printer printer;
  std::string serialized;
  EXPECT_TRUE(printer.PrintToString(m, &serialized));
  TextFormat::Parser parser;
  proto3_unittest::TestAllTypes out_message;
  EXPECT_TRUE(parser.ParseFromString(serialized, &out_message));
  EXPECT_THAT(out_message,
              testing::proto::TreatingNaNsAsEqual(testing::EqualsProto(m)));
}
FUZZ_TEST(TextFormatFuzzTests, PrintThenParseEqualsOriginalProto3);
```

Similarly, this HTML library ensures that escaping and unescaping text produces
the same input back again.

```c++
void EscapeStringForPREThenUnescapeStringEqualsOriginal(const std::string& s) {
  EXPECT_THAT(UnescapeString(EscapeStringForPRE(s)), testing::StrEq(s));
}
FUZZ_TEST(TagUtilsFuzzTests,
          EscapeStringForPREThenUnescapeStringEqualsOriginal);
```