// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./fuzztest/internal/type_support.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <complex>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/strip.h"
#include "absl/time/time.h"
#include "./fuzztest/domain.h"
#include "./fuzztest/internal/test_protobuf.pb.h"

namespace fuzztest::internal {
namespace {

using ::testing::AllOf;
using ::testing::Contains;
using ::testing::Each;
using ::testing::ElementsAre;
using ::testing::EndsWith;
using ::testing::HasSubstr;
using ::testing::Le;
using ::testing::MatchesRegex;

template <typename Domain>
std::vector<std::string> TestPrintValue(const corpus_type_t<Domain>& value,
                                        const Domain& domain) {
  std::vector<std::string> res(2);
  PrintValue(domain, value, &res[0], PrintMode::kHumanReadable);
  PrintValue(domain, value, &res[1], PrintMode::kSourceCode);
  return res;
}

template <typename T>
std::vector<std::string> TestPrintValue(const T& value) {
  std::vector<std::string> res(2);
  auto traits = AutodetectTypePrinter<T>();
  traits.PrintUserValue(value, &res[0], PrintMode::kHumanReadable);
  traits.PrintUserValue(value, &res[1], PrintMode::kSourceCode);
  return res;
}

TEST(BoolTest, Printer) {
  EXPECT_THAT(TestPrintValue(false), Each("false"));
  EXPECT_THAT(TestPrintValue(true), Each("true"));
}

TEST(CharTest, Printer) {
  EXPECT_THAT(TestPrintValue('a'), ElementsAre("'a' (97)", "'a'"));
  EXPECT_THAT(TestPrintValue(static_cast<char>(200)),
              ElementsAre("0xc8 (200)", "'\\310'"));
  EXPECT_THAT(TestPrintValue(static_cast<char>(1)),
              ElementsAre("0x01 (1)", "'\\001'"));
}

template <typename T>
class IntegralTest : public testing::Test {};

using IntegralTypes = testing::Types<signed char, unsigned char,  //
                                     short, unsigned short,       //
                                     int, unsigned int,           //
                                     long, unsigned long,         //
                                     long long, unsigned long long>;

TYPED_TEST_SUITE(IntegralTest, IntegralTypes);

TYPED_TEST(IntegralTest, Printer) {
  for (auto v : {TypeParam{0}, std::numeric_limits<TypeParam>::min(),
                 std::numeric_limits<TypeParam>::max()}) {
    EXPECT_THAT(TestPrintValue(v), Each(std::to_string(v)));
  }
}

enum Color { kRed, kBlue, kGreen };
enum ColorChar : char { kRedChar = 'r', kBlueChar = 'b' };
enum class ColorClass { kRed, kBlue, kGreen };
enum class ColorClassChar : char { kRed = 'r', kBlue = 'b' };
TEST(EnumTest, Printer) {
  EXPECT_THAT(TestPrintValue(kRed),
              ElementsAre("Color{0}", "static_cast<Color>(0)"));
  EXPECT_THAT(
      TestPrintValue(kRedChar),
      ElementsAre("ColorChar{'r' (114)}", "static_cast<ColorChar>('r')"));
  EXPECT_THAT(TestPrintValue(ColorClass::kRed),
              ElementsAre("ColorClass{0}", "static_cast<ColorClass>(0)"));
  EXPECT_THAT(TestPrintValue(ColorClassChar::kRed),
              ElementsAre("ColorClassChar{'r' (114)}",
                          "static_cast<ColorClassChar>('r')"));
}

template <typename T>
class FloatingTest : public testing::Test {};

using FloatingTypes = testing::Types<float, double, long double>;

TYPED_TEST_SUITE(FloatingTest, FloatingTypes);

TYPED_TEST(FloatingTest, Printer) {
  std::string_view suffix = std::is_same_v<float, TypeParam>    ? "f"
                            : std::is_same_v<double, TypeParam> ? ""
                                                                : "L";
  EXPECT_THAT(TestPrintValue(TypeParam{0}), Each(absl::StrCat("0.", suffix)));
  for (auto v : {std::numeric_limits<TypeParam>::min(),
                 std::numeric_limits<TypeParam>::max()}) {
    EXPECT_THAT(TestPrintValue(v),
                Each(AllOf(HasSubstr("e"), Contains('.').Times(Le(1)),
                           EndsWith(suffix))));
  }
  TypeParam inf = std::numeric_limits<TypeParam>::infinity();
  auto type = GetTypeName<TypeParam>();
  EXPECT_THAT(TestPrintValue(inf),
              ElementsAre(absl::StrFormat("%f", inf),
                          absl::StrFormat("std::numeric_limits<%s>::infinity()",
                                          type)));
  EXPECT_THAT(TestPrintValue(-inf),
              ElementsAre(absl::StrFormat("%f", -inf),
                          absl::StrFormat(
                              "-std::numeric_limits<%s>::infinity()", type)));
  TypeParam nan = std::nan("");
  EXPECT_THAT(
      TestPrintValue(nan),
      ElementsAre(absl::StrFormat("%f", nan),
                  std::is_same_v<float, TypeParam>    ? "std::nanf(\"\")"
                  : std::is_same_v<double, TypeParam> ? "std::nan(\"\")"
                                                      : "std::nanl(\"\")"));

  // Check round tripping.
  for (auto v : {TypeParam{0.0013660046866830892},
                 std::numeric_limits<TypeParam>::epsilon()}) {
    auto printed_v = TestPrintValue(v);
    std::stringstream human_v_str;
    std::stringstream source_code_v_str;
    human_v_str << absl::StripSuffix(printed_v[0], suffix);
    source_code_v_str << absl::StripSuffix(printed_v[1], suffix);
    TypeParam human_v = TypeParam{0};
    TypeParam source_code_v = TypeParam{0};
    ASSERT_TRUE(human_v_str >> human_v);
    ASSERT_TRUE(source_code_v_str >> source_code_v);
    EXPECT_EQ(v, human_v);
    EXPECT_EQ(v, source_code_v);
  }
}

TEST(StringTest, Printer) {
  EXPECT_THAT(TestPrintValue(std::string("ABC")), Each("\"ABC\""));
  EXPECT_THAT(
      TestPrintValue(std::string{'\0', 'a', '\223', 'b'}),
      ElementsAre(R"("\000a\223b")", R"(std::string("\000a\223b", 4))"));
  EXPECT_THAT(TestPrintValue(std::string("printf(\"Hello, world!\");")),
              ElementsAre(R"("printf("Hello, world!");")",
                          R"("printf(\"Hello, world!\");")"));
}

TEST(CompoundTest, Printer) {
  EXPECT_THAT(
      TestPrintValue(std::pair(1, 1.5), Arbitrary<std::pair<int, double>>()),
      Each("{1, 1.5}"));
  EXPECT_THAT(TestPrintValue(std::tuple(2, -3, -0.0),
                             Arbitrary<std::tuple<int, int, double>>()),
              Each("{2, -3, -0.}"));

  struct UserDefined {
    int i;
    double d;
    std::string s;
  };
  EXPECT_THAT(TestPrintValue(
                  std::tuple{2, -3.5, "Foo"},
                  StructOf<UserDefined>(Arbitrary<int>(), Arbitrary<double>(),
                                        Arbitrary<std::string>())),
              Each("{2, -3.5, \"Foo\"}"));
}

TEST(ProtobufTest, Printer) {
  internal::TestProtobuf proto;
  proto.set_b(true);
  proto.add_rep_subproto()->set_subproto_i32(17);
  EXPECT_THAT(TestPrintValue(proto),
              ElementsAre(absl::StrCat("(", proto.ShortDebugString(), ")"),
                          absl::StrCat("ParseTestProto(R\"pb(",
                                       proto.ShortDebugString(), ")pb\")")));
}

TEST(ProtobufEnumTest, Printer) {
  auto domain = Arbitrary<internal::TestProtobuf_Enum>();
  EXPECT_THAT(TestPrintValue(TestProtobuf_Enum_Label2, domain),
              ElementsAre("fuzztest::internal::TestProtobuf::Label2 (1)",
                          "fuzztest::internal::TestProtobuf::Label2"));

  domain = Arbitrary<internal::TestProtobuf::Enum>();
  EXPECT_THAT(TestPrintValue(TestProtobuf::Label3, domain),
              ElementsAre("fuzztest::internal::TestProtobuf::Label3 (2)",
                          "fuzztest::internal::TestProtobuf::Label3"));

  EXPECT_THAT(
      TestPrintValue(static_cast<internal::TestProtobuf_Enum>(100), domain),
      ElementsAre("fuzztest::internal::TestProtobuf_Enum{100}",
                  "static_cast<fuzztest::internal::TestProtobuf_Enum>(100)"));

  auto bare_domain = Arbitrary<internal::BareEnum>();
  EXPECT_THAT(TestPrintValue(internal::BareEnum::LABEL_OTHER, bare_domain),
              ElementsAre("fuzztest::internal::BareEnum::LABEL_OTHER (10)",
                          "fuzztest::internal::BareEnum::LABEL_OTHER"));
}

TEST(ContainerTest, Printer) {
  EXPECT_THAT(
      TestPrintValue(std::vector{1, 2, 3}, Arbitrary<std::vector<int>>()),
      Each("{1, 2, 3}"));
  EXPECT_THAT(TestPrintValue(*Arbitrary<std::set<int>>().FromValue({1, 2, 3}),
                             Arbitrary<std::set<int>>()),
              Each("{1, 2, 3}"));
  EXPECT_THAT(TestPrintValue(
                  *Arbitrary<std::map<int, int>>().FromValue({{1, 2}, {2, 3}}),
                  Arbitrary<std::map<int, int>>()),
              Each("{{1, 2}, {2, 3}}"));

  // With custom inner
  auto inner = ElementOf({kGreen, kRed});
  using InnerCorpusT = corpus_type_t<decltype(inner)>;
  EXPECT_THAT(TestPrintValue(
                  std::list{InnerCorpusT{0}, InnerCorpusT{0}, InnerCorpusT{1}},
                  ContainerOf<std::vector<Color>>(inner)),
              ElementsAre("{Color{2}, Color{2}, Color{0}}",
                          "{static_cast<Color>(2), static_cast<Color>(2), "
                          "static_cast<Color>(0)}"));
}

TEST(DomainTest, Printer) {
  // Make sure we can print through the type erased Domain<T>
  auto color_domain = ElementOf({kBlue});
  auto print = [&](auto v, auto domain) {
    // We have to create the inner corpus_type of Domain here.
    return TestPrintValue(
        corpus_type_t<decltype(domain)>(std::in_place_type<decltype(v)>, v),
        domain);
  };
  EXPECT_THAT(print('a', Domain<char>(Arbitrary<char>())),
              ElementsAre("'a' (97)", "'a'"));
  EXPECT_THAT(print(typename decltype(color_domain)::corpus_type{0},
                    Domain<Color>(color_domain)),
              ElementsAre("Color{1}", "static_cast<Color>(1)"));
}

TEST(VariantTest, Printer) {
  using V = std::variant<int, double, std::vector<std::string>>;
  V value;
  auto variant_domain = VariantOf<V>(
      Arbitrary<int>(), Arbitrary<double>(),
      ContainerOf<std::vector<std::string>>(Arbitrary<std::string>()));
  value = 1;
  EXPECT_THAT(TestPrintValue(value, variant_domain),
              ElementsAre("(index=0, value=1)", "1"));
  value = 1.2;
  EXPECT_THAT(TestPrintValue(value, variant_domain),
              ElementsAre("(index=1, value=1.2)", "1.2"));
  value = std::vector<std::string>{"variant", "print", "test"};
  EXPECT_THAT(TestPrintValue(value, variant_domain),
              ElementsAre("(index=2, value={\"variant\", \"print\", \"test\"})",
                          "{\"variant\", \"print\", \"test\"}"));
}

TEST(OptionalTest, Printer) {
  auto optional_int_domain = OptionalOf(Arbitrary<int>());
  EXPECT_THAT(TestPrintValue({}, optional_int_domain), Each("std::nullopt"));
  EXPECT_THAT(TestPrintValue(1, optional_int_domain), ElementsAre("(1)", "1"));

  auto optional_string_domain = OptionalOf(Arbitrary<std::string>());
  EXPECT_THAT(TestPrintValue({}, optional_string_domain), Each("std::nullopt"));
  EXPECT_THAT(TestPrintValue("ABC", optional_string_domain),
              ElementsAre("(\"ABC\")", "\"ABC\""));
}

TEST(SmartPointerTest, Printer) {
  EXPECT_THAT(TestPrintValue({}, Arbitrary<std::unique_ptr<int>>()),
              Each("nullptr"));
  EXPECT_THAT(
      TestPrintValue(Domain<int>::corpus_type(std::in_place_type<int>, 7),
                     Arbitrary<std::unique_ptr<int>>()),
      ElementsAre("(7)", "std::make_unique<int>(7)"));
  EXPECT_THAT(
      TestPrintValue(Domain<std::string>::corpus_type(
                         std::in_place_type<std::string>, "ABC"),
                     Arbitrary<std::shared_ptr<std::string>>()),
      ElementsAre(
          R"(("ABC"))",
          MatchesRegex(R"re(std::make_shared<std::.*string.*>\("ABC"\))re")));
}

TEST(OneOfTest, Printer) {
  auto domain = OneOf(ElementOf({17}), InRange(20, 22));
  using corpus_type = corpus_type_t<decltype(domain)>;

  EXPECT_THAT(TestPrintValue(corpus_type(std::in_place_index<0>), domain),
              Each("17"));
  EXPECT_THAT(TestPrintValue(corpus_type(std::in_place_index<1>, 21), domain),
              Each("21"));
}

std::string StringTimes(int n, char c) { return std::string(n, c); }

auto HexString() {
  return Map([](int number) { return absl::StrFormat("%#x", number); },
             InRange(0, 32));
}

TEST(MapTest, Printer) {
  auto domain = Map(StringTimes, InRange(2, 5), InRange('a', 'b'));
  std::tuple<int, char> corpus_value(3, 'b');

  EXPECT_THAT(TestPrintValue(corpus_value, domain),
              ElementsAre("\"bbb\"",
                          // Takes into account that the function name may
                          // contain ABI annotations after de-mangling.
                          MatchesRegex(R"re(StringTimes.*\(3, 'b'\))re")));

  // Test fallback on user value when map involves a lambda.
  EXPECT_THAT(TestPrintValue(std::tuple<int>(21), HexString()),
              Each("\"0x15\""));
}

auto ValueInRange(int a, int b) {
  int min = std::min(a, b);
  int max = std::max(a, b);
  return InRange(min, max);
}

TEST(FlatMapTest, PrinterWithNamedFunction) {
  auto domain = FlatMap(ValueInRange, Arbitrary<int>(), Arbitrary<int>());
  decltype(domain)::corpus_type corpus_value = {2, 3, 1};
  EXPECT_THAT(TestPrintValue(corpus_value, domain),
              ElementsAre("2", "ValueInRange(3, 1)"));
}

TEST(FlatMapTest, PrinterWithLambda) {
  auto domain =
      FlatMap([](int a) { return ValueInRange(a, a + 100); }, Arbitrary<int>());
  decltype(domain)::corpus_type corpus_value = {42, 0};
  EXPECT_THAT(TestPrintValue(corpus_value, domain), Each("42"));
}

auto VectorWithSize(int size) {
  return VectorOf(Arbitrary<int>()).WithSize(size);
}

TEST(FlatMapTest, PrintVector) {
  auto domain = FlatMap(VectorWithSize, InRange(2, 4));
  decltype(domain)::corpus_type corpus_value = {{1, 2, 3}, 3};

  EXPECT_THAT(TestPrintValue(corpus_value, domain),
              ElementsAre("{1, 2, 3}", "VectorWithSize(3)"));

  auto lambda = [](int size) { return VectorWithSize(size); };
  auto lambda_domain = FlatMap(lambda, InRange(2, 4));
  EXPECT_THAT(TestPrintValue(corpus_value, lambda_domain),
              ElementsAre("{1, 2, 3}", "{1, 2, 3}"));
}

TEST(ConstructorOfTest, Printer) {
  EXPECT_THAT(
      TestPrintValue({3, 'b'}, ConstructorOf<std::string>(InRange(0, 5),
                                                          Arbitrary<char>())),
      ElementsAre("\"bbb\"", MatchesRegex(R"re(std::.*string.*\(3, 'b'\))re")));
  EXPECT_THAT(TestPrintValue(
                  {-1}, ConstructorOf<std::complex<float>>(Arbitrary<float>())),
              ElementsAre("(-1,0)", "std::complex<float>(-1.f)"));

  struct UserDefined {};
  EXPECT_THAT(TestPrintValue({}, ConstructorOf<UserDefined>()),
              ElementsAre("{}", "UserDefined()"));
}

TEST(MonostateTest, Printer) {
  struct UserDefinedEmpty {};
  EXPECT_THAT(TestPrintValue(std::monostate{}), Each("{}"));
  EXPECT_THAT(TestPrintValue(std::tuple{}), Each("{}"));
  EXPECT_THAT(TestPrintValue(std::array<int, 0>{}), Each("{}"));
  EXPECT_THAT(TestPrintValue(UserDefinedEmpty{}), Each("{}"));
}

struct AggregateStructWithNoAbslStringify {
  int i = 1;
  std::pair<std::string, std::string> nested = {"Foo", "Bar"};
};

struct AggregateStructWithAbslStringify {
  int i = 1;
  std::pair<std::string, std::string> nested = {"Foo", "Bar"};

  template <typename Sink>
  friend void AbslStringify(Sink& sink,
                            const AggregateStructWithAbslStringify& s) {
    absl::Format(&sink, "value={%d, {%s, %s}}", s.i, s.nested.first,
                 s.nested.second);
  }
};

TEST(AutodetectAggregateTest, Printer) {
  // MonostateTest handles empty tuple and array.

  EXPECT_THAT(TestPrintValue(std::tuple{123}), Each("{123}"));
  EXPECT_THAT(TestPrintValue(std::pair{123, 456}), Each("{123, 456}"));
  EXPECT_THAT(TestPrintValue(std::array{123, 456}), Each("{123, 456}"));
  EXPECT_THAT(TestPrintValue(AggregateStructWithNoAbslStringify{}),
              Each(R"({1, {"Foo", "Bar"}})"));
  EXPECT_THAT(TestPrintValue(AggregateStructWithAbslStringify{}),
              ElementsAre("value={1, {Foo, Bar}}", R"({1, {"Foo", "Bar"}})"));
}

TEST(DurationTest, Printer) {
  EXPECT_THAT(TestPrintValue(absl::InfiniteDuration()),
              ElementsAre("inf", "absl::InfiniteDuration()"));
  EXPECT_THAT(TestPrintValue(-absl::InfiniteDuration()),
              ElementsAre("-inf", "-absl::InfiniteDuration()"));
  EXPECT_THAT(TestPrintValue(absl::ZeroDuration()),
              ElementsAre("0", "absl::ZeroDuration()"));
  EXPECT_THAT(TestPrintValue(absl::Seconds(1)),
              ElementsAre("1s", "absl::Seconds(1)"));
  EXPECT_THAT(TestPrintValue(absl::Milliseconds(1500)),
              ElementsAre("1.5s",
                          "absl::Seconds(1) + "
                          "absl::Nanoseconds(500000000)"));
  EXPECT_THAT(TestPrintValue(absl::Nanoseconds(-0.25)),
              ElementsAre("-0.25ns",
                          "absl::Seconds(-1) + "
                          "(absl::Nanoseconds(1) / 4) * 3999999999"));
}

TEST(TimeTest, Printer) {
  EXPECT_THAT(TestPrintValue(absl::InfinitePast()),
              ElementsAre("infinite-past", "absl::InfinitePast()"));
  EXPECT_THAT(TestPrintValue(absl::InfiniteFuture()),
              ElementsAre("infinite-future", "absl::InfiniteFuture()"));
  EXPECT_THAT(TestPrintValue(absl::UnixEpoch()),
              ElementsAre("1970-01-01T00:00:00+00:00", "absl::UnixEpoch()"));
  EXPECT_THAT(TestPrintValue(absl::FromUnixSeconds(1577836800)),
              ElementsAre("2020-01-01T00:00:00+00:00",
                          "absl::UnixEpoch() + absl::Seconds(1577836800)"));
  EXPECT_THAT(TestPrintValue(absl::FromUnixSeconds(-1290000)),
              ElementsAre("1969-12-17T01:40:00+00:00",
                          "absl::UnixEpoch() + absl::Seconds(-1290000)"));
}

struct NonAggregateStructWithNoAbslStringify {
  NonAggregateStructWithNoAbslStringify() : i(1), nested("Foo", "Bar") {}
  int i;
  std::pair<std::string, std::string> nested;
};

struct NonAggregateStructWithAbslStringify {
  NonAggregateStructWithAbslStringify() : i(1), nested("Foo", "Bar") {}
  int i;
  std::pair<std::string, std::string> nested;

  template <typename Sink>
  friend void AbslStringify(Sink& sink,
                            const NonAggregateStructWithAbslStringify& s) {
    absl::Format(&sink, "value={%d, {%s, %s}}", s.i, s.nested.first,
                 s.nested.second);
  }
};

TEST(UnprintableTest, Printer) {
  EXPECT_THAT(TestPrintValue(NonAggregateStructWithNoAbslStringify{}),
              Each("<unprintable value>"));
  EXPECT_THAT(TestPrintValue(NonAggregateStructWithAbslStringify{}),
              ElementsAre("value={1, {Foo, Bar}}", "<unprintable value>"));
  EXPECT_THAT(
      TestPrintValue(std::vector<NonAggregateStructWithNoAbslStringify>{}),
      Each("<unprintable value>"));
  EXPECT_THAT(
      TestPrintValue(std::vector<NonAggregateStructWithAbslStringify>{}),
      Each("<unprintable value>"));
}

}  // namespace
}  // namespace fuzztest::internal
