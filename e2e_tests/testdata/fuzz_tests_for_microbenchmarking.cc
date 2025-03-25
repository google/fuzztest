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

// Small fuzz test examples for micro-benchmarking (and functional testing).
//
// The fuzz tests in this file are used by two higher level tests:
//
// (1) The `benchmark_test` uses these fuzz tests to benchmark the fuzzer, i.e.,
// to measure the number of iterations/time necessary to reach the "abort()"
// branch or some bug.
//
// (2) The `functional_test` uses them for basic functional end-to-end testing,
// i.e., to check that the fuzzer behaves as expected and outputs the expected
// results. E.g., the fuzzer finds the abort() or bug.

#include <array>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "./fuzztest/fuzztest.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/internal/test_protobuf.pb.h"

volatile int googlefuzz_force_write;

namespace {

// A microbenchmark to use as a baseline reference point.
void Iters10000(std::true_type) {
  static int i = 0;
  if (++i == 10000) std::abort();
}
FUZZ_TEST(Control, Iters10000);

// We use this test to make sure we catch buffer overflows.
void BufferOverread(std::string_view s) {
  if (s.empty()) return;
  size_t out_of_bounds_index = s.size();
  googlefuzz_force_write = s.data()[out_of_bounds_index];
}

void BufferOverreadWithStringView(std::string_view s) { BufferOverread(s); }
FUZZ_TEST(MySuite, BufferOverreadWithStringView)
    .WithDomains(fuzztest::Arbitrary<std::string_view>());

void BufferOverreadWithString(std::string_view s) { BufferOverread(s); }
FUZZ_TEST(MySuite, BufferOverreadWithString)
    .WithDomains(fuzztest::Arbitrary<std::string>());

void BufferOverreadWithStringAndLvalueStringViewRef(const std::string_view& s) {
  BufferOverread(s);
}
FUZZ_TEST(MySuite, BufferOverreadWithStringAndLvalueStringViewRef)
    .WithDomains(fuzztest::Arbitrary<std::string>());

void BufferOverreadWithStringAndRvalueStringViewRef(std::string_view&& s) {
  BufferOverread(std::move(s));
}
FUZZ_TEST(MySuite, BufferOverreadWithStringAndRvalueStringViewRef)
    .WithDomains(fuzztest::Arbitrary<std::string>());

void DereferenceEmptyOptional(std::optional<int> i) {
  if (!i.has_value()) {
    googlefuzz_force_write = *i;
  }
}
FUZZ_TEST(MySuite, DereferenceEmptyOptional);

// Always disable optimization for this example, otherwise (when optimization is
// enabled) SanCov doesn't instrument all edges (and therefore no feedback).
// TODO(b/182297432): Make this unnecessary.
__attribute__((optnone)) void Coverage(char a, char b, char c, char d) {
  if (a == 'F') {
    if (b == 'u') {
      if (c == 'z') {
        if (d == 'z') {
          // Use an assert to test that these are caught in fuzzing mode, even
          // when built with optimization.
          assert(a == b);
        }
      }
    }
  }
}
FUZZ_TEST(MySuite, Coverage);

void DivByZero(int8_t numerator, int8_t denominator) {
  googlefuzz_force_write = denominator != -1 && numerator / denominator != 0;
}
FUZZ_TEST(MySuite, DivByZero);

__attribute__((optnone)) void FindString(const std::string& in) {
  // Do one character at a time to have one edge per char.
  // No need to check for length, because for std::string s, s.[s.size()]
  // returns null character.
  if (in[0] == 'F' && in[1] == 'u' && in[2] == 'z' && in[3] == 'z') {
    std::abort();
  }
}

void String(const std::string& in) { FindString(in); }
FUZZ_TEST(MySuite, String);

void StringFast(const std::string& in) { FindString(in); }
FUZZ_TEST(MySuite, StringFast)
    .WithDomains(fuzztest::Arbitrary<std::string>().WithSize(4));

// TODO(changochen): Replace it with better test function
void StringAsciiOnly(const std::string& in) { FindString(in); }
FUZZ_TEST(MySuite, StringAsciiOnly).WithDomains(fuzztest::AsciiString());

// TODO(changochen): Replace it with better test function
__attribute__((optnone)) void StringRegexp(const std::string& in) {
  FindString(in);
}
FUZZ_TEST(MySuite, StringRegexp).WithDomains(fuzztest::InRegexp("[A-Za-z]{4}"));

__attribute__((optnone)) void StringView(std::string_view in) {
  // Do one character at a time to have one edge per char.
  if (in.size() >= 4 && in[0] == 'F' && in[1] == 'u' && in[2] == 'z' &&
      in[3] == 'z') {
    std::abort();
  }
}
FUZZ_TEST(MySuite, StringView)
    .WithDomains(fuzztest::Arbitrary<std::string>().WithMaxSize(20));

__attribute__((optnone)) void StrCmp(const std::string& s) {
  if (strcmp(s.c_str(), "Hello!") == 0) {
    std::abort();
  }
}

FUZZ_TEST(MySuite, StrCmp);

__attribute__((optnone)) void BitFlags(int bits) {
  if ((bits & (1 << 0)) != 0 && (bits & (1 << 1)) == 0 &&
      (bits & (1 << 2)) != 0 && (bits & (1 << 3)) == 0 &&
      (bits & (1 << 4)) != 0 && (bits & (1 << 5)) == 0) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, BitFlags)
    .WithDomains(fuzztest::BitFlagCombinationOf({1 << 0, 1 << 1, 1 << 2, 1 << 3,
                                                 1 << 4, 1 << 5}));

enum Color { red, green, blue };
auto AnyColor() { return fuzztest::ElementOf({red, green, blue}); }
__attribute__((optnone)) void EnumValue(Color a, Color b, Color c) {
  if (a == red) {
    if (b == green) {
      if (c == blue) {
        std::abort();
      }
    }
  }
}
FUZZ_TEST(MySuite, EnumValue).WithDomains(AnyColor(), AnyColor(), AnyColor());

enum class ColorClass { red, green, blue };
auto AnyColorClass() {
  return fuzztest::ElementOf(
      {ColorClass::red, ColorClass::green, ColorClass::blue});
}
__attribute__((optnone)) void EnumClassValue(ColorClass a, ColorClass b,
                                             ColorClass c) {
  if (a == ColorClass::red) {
    if (b == ColorClass::green) {
      if (c == ColorClass::blue) {
        std::abort();
      }
    }
  }
}
FUZZ_TEST(MySuite, EnumClassValue)
    .WithDomains(AnyColorClass(), AnyColorClass(), AnyColorClass());

__attribute__((optnone)) void Proto(
    const fuzztest::internal::TestProtobuf& proto) {
  if (proto.b() &&                                             //
      proto.subproto().subproto_i32() > 1 &&                   //
      !proto.rep_i64().empty() && proto.rep_i64()[0] == -1 &&  //
      !proto.rep_subproto().empty() &&
      proto.rep_subproto(0).subproto_i32() > 0x12345 &&
      proto.e() == proto.Label2) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, Proto);

__attribute__((optnone)) void BitvectorValue(const std::vector<bool>& v) {
  if (v == std::vector<bool>{true, false, true, false}) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, BitvectorValue);

__attribute__((optnone)) void VectorValue(const std::vector<char>& v) {
  if (v == std::vector<char>{'F', 'u', 'z', 'z'}) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, VectorValue)
    .WithDomains(
        fuzztest::VectorOf(fuzztest::Arbitrary<char>()).WithMaxSize(20));

constexpr auto& FixedSizeVectorValue = VectorValue;
FUZZ_TEST(MySuite, FixedSizeVectorValue)
    .WithDomains(fuzztest::VectorOf(fuzztest::Arbitrary<char>()).WithSize(4));

__attribute__((optnone)) void BitGenRef(absl::BitGenRef bitgen) {
  if (absl::Uniform(bitgen, 0, 256) == 'F' &&
      absl::Uniform(bitgen, 0, 256) == 'U' &&
      absl::Uniform(bitgen, 0, 256) == 'Z' &&
      absl::Uniform(bitgen, 0, 256) == 'Z') {
    std::abort();  // Bug!
  }
}
FUZZ_TEST(MySuite, BitGenRef);

__attribute__((optnone)) void WithDomainClass(uint8_t a, double d) {
  // This will only crash with a=10, to make it easier to check the results.
  // d can have any value.
  if (a > 10) return;
  int x = 1000;
  while (a > 0) {
    --a;
    x /= 2;
    d = a / x;
    static_cast<void>(d);  // Silence -Wunused-but-set-parameter
  }
}
FUZZ_TEST(MySuite, WithDomainClass)
    .WithDomains(fuzztest::Domain<uint8_t>(fuzztest::Arbitrary<uint8_t>()),
                 fuzztest::Domain<double>(fuzztest::Arbitrary<double>()));

std::string NumberOfAnimalsToString(int num, std::string_view name) {
  // Explicit conversion to absl::string_view is for platforms where these two
  // types are not the same.
  return absl::StrFormat("%d %ss", num,
                         absl::string_view{name.data(), name.size()});
}
int TimesTwo(int x) { return 2 * x; }

fuzztest::Domain<std::string> EvenNumberOfAnimals() {
  return fuzztest::Map(
      NumberOfAnimalsToString, fuzztest::Map(TimesTwo, fuzztest::InRange(1, 6)),
      fuzztest::ElementOf<std::string_view>({"dog", "cat", "monkey"}));
}
void Mapping(const std::string& s) {
  if (s == "12 monkeys") std::abort();
}
FUZZ_TEST(MySuite, Mapping).WithDomains(EvenNumberOfAnimals());

auto StringAndValidIndex(const std::string& s) {
  return fuzztest::PairOf(fuzztest::Just(s),
                          fuzztest::InRange<size_t>(0, s.size() - 1));
}
auto AnyStringAndValidIndex() {
  auto string_domain =
      fuzztest::StringOf(fuzztest::InRange('a', 'z')).WithSize(3);
  return fuzztest::FlatMap(StringAndValidIndex, string_domain);
}
void FlatMapping(const std::pair<std::string, size_t> str_and_idx) {
  std::string_view str = str_and_idx.first;
  size_t idx = str_and_idx.second;
  if (str == "abc" && idx == 2) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, FlatMapping).WithDomains(AnyStringAndValidIndex());

void Filtering(int multiple_of_2, int square) {
  // Should only fail with (8, 9)
  if (multiple_of_2 + 1 == square) std::abort();
}
auto MultiplesOfTwo() {
  auto is_even = [](int i) { return i % 2 == 0; };
  return fuzztest::Filter(is_even, fuzztest::InRange(1, 10));
}
auto Squares() {
  auto is_square = [](int i) {
    return std::pow(std::floor(std::sqrt(i)), 2) == i;
  };
  return fuzztest::Filter(is_square, fuzztest::InRange(1, 10));
}
FUZZ_TEST(MySuite, Filtering).WithDomains(MultiplesOfTwo(), Squares());

void SmartPointer(std::unique_ptr<int> i) {
  if (i && absl::StrCat(*i)[0] == '1') std::abort();
}
FUZZ_TEST(MySuite, SmartPointer);

void Minimizer(const std::string& input) {
  if (input.find('X') != input.npos) std::abort();
}
FUZZ_TEST(MySuite, Minimizer);

struct MyStruct {
  uint8_t a;
  std::string b;
};

void MyStructArbitrary(MyStruct s) {
  if (s.a == 0 && s.b[0] == 'X') std::abort();
}
FUZZ_TEST(MySuite, MyStructArbitrary);

void MyStructWithDomains(MyStruct s) {
  if (s.a == 0 && s.b[0] == 'X') std::abort();
}
FUZZ_TEST(MySuite, MyStructWithDomains)
    .WithDomains(fuzztest::StructOf<MyStruct>(
        fuzztest::Arbitrary<uint8_t>(), fuzztest::Arbitrary<std::string>()));

auto RepeatedStringDomain() {
  return fuzztest::ConstructorOf<std::string>(fuzztest::InRange(1, 5),
                                              fuzztest::InRange('a', 'c'));
}
void ConstructorWithDomains(const std::string& s) {
  if (s == "ccc") abort();
}
FUZZ_TEST(MySuite, ConstructorWithDomains).WithDomains(RepeatedStringDomain());

auto SeedInputIsUsedForMutation(const std::vector<uint32_t>& s) {
  // Make it very hard for coverage to find the value without mutating from the
  // seed. Will only abort() if seed input is mutated, i.e., if the 5th element
  // `0xbad` is removed/changed.
  if (s.size() < 4) return;
  if (s[0] == 0 || s[1] == 0 || s[2] == 0 || s[3] == 0) return;
  if (s[0] >= 10000 || s[1] >= 10000 || s[2] >= 10000 || s[3] >= 10000) return;
  if (s[0] * 9791 != 1979 * s[1]) return;
  if (1234 * s[3] != s[2] * 6789) return;
  if (s.size() > 4 && s[4] == 0xbad) return;
  std::abort();
}
FUZZ_TEST(MySuite, SeedInputIsUsedForMutation)
    .WithSeeds({{{1979, 9791, 1234, 6789, 0xbad}}});

// Testing cmp coverage.
// Matching magic values for cmp instructions.
auto Int32ValueTest(int x) {
  if (x == 0xdeadbeef) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, Int32ValueTest);

// Testing cmp coverage.
// Matching magic values for switch instructions.
auto SwitchTest(unsigned int x) {
  switch (x) {
    case 0xbaadf00d:
      abort();
    case 0xdeadbeef:
      abort();
    default:
      break;
  }
}
FUZZ_TEST(MySuite, SwitchTest);

// Enabled by including absolute distance in the CMP coverage score.
// Path-dependent-on-states could be somehow explored by a fair
// scoring of the state data. With Absolute distance, this test will be
// captured.
auto PathDependentState(char a, char b, char c, char d) {
  int counter = 0;
  if (a == 'f') counter++;
  if (b == 'u') counter++;
  if (c == 'z') counter++;
  if (d == 'z') counter++;
  if (counter == 4) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, PathDependentState);

// Testing new mutation of InRange domain
// works correctly.
auto Int32ValueInRangeTest(unsigned int x) {
  if (x == 0x00110000) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, Int32ValueInRangeTest)
    .WithDomains(fuzztest::InRange(0x00100000U, 0x00111111U));

auto BasicStringCmpTest(std::string_view encoded_data) {
  if (encoded_data.size() < 8) {
    return;
  } else if (encoded_data.substr(0, 8) == "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a") {
    std::abort();
  }
}
FUZZ_TEST(MySuite, BasicStringCmpTest);

auto SimpleFormatParsingTest(std::string_view encoded_data) {
  if (encoded_data.size() < 72) {
    return;
  } else if (encoded_data.substr(0, 5) == "GUARD") {
    if (encoded_data.substr(67, 72) == "DRAUG") {
      // Put the magic number check in a random place and protected by guards
      // so it will be very hard to find with random mutations.
      const size_t magic_number_field =
          *reinterpret_cast<const uint32_t*>(encoded_data.data() + 27);
      if (magic_number_field == 0xdeadbeef) {
        std::abort();
      }
    }
  }
}
FUZZ_TEST(MySuite, SimpleFormatParsingTest);

// To test the manual dictionary. The dynamic (automatic) dictionary feature
// would not be effective cracking this, as we are comparing to the permuted
// string.
void StringPermutationTest(const std::string& encoded_data) {
  static constexpr std::array perm = {2, 1, 9, 0, 3, 6, 5, 4, 8, 7};
  if (encoded_data.size() >= perm.size()) {
    std::string permuted = encoded_data;
    for (size_t i = 0; i < perm.size(); ++i) {
      permuted[i] = encoded_data[perm[i]];
    }
    // The string "9876543210" maps to this.
    if (permuted == "7809634512") {
      std::abort();
    }
  }
}
FUZZ_TEST(MySuite, StringPermutationTest)
    .WithDomains(
        fuzztest::Arbitrary<std::string>().WithDictionary({"9876543210"}));

// Like the manual dictionary test, but with a seeded domain.
void StringPermutationWithSeeds(const std::string& encoded_data) {
  StringPermutationTest(encoded_data);
}
FUZZ_TEST(MySuite, StringPermutationWithSeeds)
    .WithDomains(fuzztest::Arbitrary<std::string>().WithSeeds({"9876543210"}));

void StringPermutationWithSeedProvider(const std::string& encoded_data) {
  StringPermutationTest(encoded_data);
}
FUZZ_TEST(MySuite, StringPermutationWithSeedProvider)
    .WithSeeds([]() -> std::vector<std::tuple<std::string>> {
      return {{"9876543210"}};
    });

struct SeededFixture {
  std::vector<std::tuple<std::string>> GetSeeds() { return {{"9876543210"}}; }

  void StringPermutationWithSeedProvider(const std::string& encoded_data) {
    StringPermutationTest(encoded_data);
  }
};
FUZZ_TEST_F(SeededFixture, StringPermutationWithSeedProvider)
    .WithSeeds(&SeededFixture::GetSeeds);

////////////////////////////////////////////////////////////////////////////////
// Examples to get working.
#if 0
// Here we collect examples that are not working yet, but we'd like them to
// work. Once an example is working, we move it out above.

// Matching values.

FUZZ_TEST(MySuite, Int64Value, (uint64_t x)) {
  if (x == 0xdeadbeefcafeface) {
    std::abort();
  }
}

FUZZ_TEST(MySuite, DoubleValue, (double x)) {
  if (x == 3.14) {
    std::abort();
  }
}

FUZZ_TEST(MySuite, StringValue, (const std::string& s)) {
  if (s == "Hello world!") {
    std::abort();
  }
}

FUZZ_TEST(MySuite, StringSize, (const std::string& s)) {
  if (s.size >= 100) {
    std::abort();
  }
}

FUZZ_TEST(MySuite, StringPartialValue, (const std::string& s)) {
  if (s.size >= 100 && s[16] == 'f' && s[32] == 'u' && s[48] =
          'z' && s[64] == 'z') {
    std::abort();
  }
}

struct Order {
  std::string item;
  int quantity;
}

FUZZ_TEST(MySuite, StructValue, (const Order& o)) {
  if (o.item == "bla" && o.quantity == 3) {
    std::abort();
  }
}

FUZZ_TEST(MySuite, ProtoValue, (const MyProtoMessage& msg)) {
  MyProtoMessage value = ...;
  if (google::protobuf::util::MessageDifferencer::Equals(msg, value)) {
    std::abort();
  }
}

// Constraints.

FUZZ_TEST(MySuite, Divisible, (uint64_6 x)) {
  if ((x != 0) && (x % 2 == 0) && (x % 3 == 0) && (x % 5 == 0) &&
      (x % 7 == 0) && (x % 11 == 0) && (x % 13 == 0)) {
    std::abort();
  }
}

FUZZ_TEST(MySuite, Divisible, (int x, int y)) {
  // Possible solution: x = 8, y = -9.
  if (x > y) {
    if (x + y > x * y) {
      if (x < -y) {
        if (x * y != 0) {
          if (x * -2 < y) {
            if (x - 17 == y) {
              std::abort();
            }
          }
        }
      }
    }
  }
}

FUZZ_TEST(MySuite, IncreasingNumbers, (int a, int b, int c, int d)) {
  if (b == a + 1) {
    if (c == b + 1) {
      if (d == c + 1) {
        std::abort();
      }
    }
  }
}

FUZZ_TEST(MySuite, CharConstraints, (char a, char b, char c, char d)) {
  if (isalnum(a)) {
    if (isblank(b)) {
      if (isupper(c)) {
        if (ispunct(d)) {
          std::abort();
        }
      }
    }
  }
}

// Program structures.

FUZZ_TEST(MySuite, Loop, (const std::string& s)) {
  int counter = 0;
  for (int i = 0; i < s.size(), i++) {
    if (s[i] == i) {
      counter++;
    }
    if (counter >= 10) {
      std::abort();
    }
  }
}

void Recurse(const std::string& s, int i, int counter) {
  if (counter >= 10) {
    std::abort();
  }
  if (i < s.size()) {
    Recurse(s, i + 1, counter + (s[i] == i));
  }
}

FUZZ_TEST(MySuite, Recursion, (const std::string& s)) { Recurse(s, 0, 0); }

#endif  // End of "examples to get working".

}  // namespace
