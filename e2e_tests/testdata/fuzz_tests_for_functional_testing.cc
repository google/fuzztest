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

// Small fuzz test examples to be used for e2e functional testing.
//
// Specifically, used by `functional_test` only.

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "google/protobuf/descriptor.h"
#include "absl/algorithm/container.h"
#include "absl/functional/function_ref.h"
#include "absl/time/time.h"
#include "./fuzztest/fuzztest.h"
#include "./fuzztest/internal/test_protobuf.pb.h"

namespace {
using fuzztest::Arbitrary;
using fuzztest::FlatMap;
using fuzztest::InRange;
using fuzztest::Just;
using fuzztest::PairOf;
using fuzztest::StringOf;
using fuzztest::StructOf;
using fuzztest::VectorOf;
using fuzztest::internal::ProtoExtender;
using fuzztest::internal::TestProtobuf;
using fuzztest::internal::TestProtobufWithExtension;
using fuzztest::internal::TestProtobufWithRecursion;
using fuzztest::internal::TestSubProtobuf;
using google::protobuf::FieldDescriptor;

void PassesWithPositiveInput(int x) {
  if (x <= 0) std::abort();
}
FUZZ_TEST(MySuite, PassesWithPositiveInput)
    .WithDomains(fuzztest::Positive<int>());

void Aborts(int foo, int bar) {
  if (foo > bar) std::abort();
}
FUZZ_TEST(MySuite, Aborts);

void PassesString(const std::string& v) {
  fprintf(stderr, "==<<Saw size=%zu>>==\n", v.size());
}
FUZZ_TEST(MySuite, PassesString);

void BadFilter(int i) {}
FUZZ_TEST(MySuite, BadFilter)
    .WithDomains(fuzztest::Filter([](int i) { return i == 0xdeadbeef; },
                                  fuzztest::Arbitrary<int>()));

void BadWithMinSize(const std::set<char>&) {}
FUZZ_TEST(MySuite, BadWithMinSize)
    .WithDomains(fuzztest::Arbitrary<std::set<char>>().WithMinSize(300));

struct UnprintableType {
  // User-defined constructor to make this type not an aggregate.
  UnprintableType() : some_state_to_make_it_not_a_monostate() {}
  void* some_state_to_make_it_not_a_monostate;
};
void UsesUnprintableType(UnprintableType) { std::abort(); }
FUZZ_TEST(MySuite, UsesUnprintableType)
    .WithDomains(fuzztest::Just(UnprintableType{}));

void OneIterationTakesTooMuchTime(int) {
  absl::SleepFor(absl::Milliseconds(100));
  fprintf(stderr, "Takes a very long time for one iter...\n");
}
FUZZ_TEST(MySuite, OneIterationTakesTooMuchTime);

auto SeedInputIsUsed(const std::vector<int>& s) {
  if (s == std::vector<int>{0x90091E, 0x15, 0xC001}) std::abort();
}
FUZZ_TEST(MySuite, SeedInputIsUsed).WithSeeds({{{0x90091E, 0x15, 0xC001}}});

constexpr auto* FunctionPointerAliasesAreFuzzable = Aborts;
FUZZ_TEST(MySuite, FunctionPointerAliasesAreFuzzable);

constexpr auto& FunctionReferenceAliasesAreFuzzable = Aborts;
FUZZ_TEST(MySuite, FunctionReferenceAliasesAreFuzzable);

std::vector<std::tuple<TestProtobufWithExtension>> ProtoSeeds() {
  TestProtobufWithExtension result;
  result.SetExtension(ProtoExtender::ext, "some text");
  return {{result}};
}

void CheckProtoExtensions(const TestProtobufWithExtension proto) {
  if (proto.HasExtension(fuzztest::internal::ProtoExtender::ext)) {
    fprintf(stderr, "Uses proto extensions!\n");
    std::abort();
  }
}

FUZZ_TEST(MySuite, CheckProtoExtensions).WithSeeds(ProtoSeeds());

void TargetPrintSomethingThenAbrt(int a) {
  absl::FPrintF(stdout, "Hello World from target stdout\n");
  absl::FPrintF(stderr, "Hello World from target stderr\n");
  fflush(stdout);
  fflush(stderr);
  if (a > 42) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, TargetPrintSomethingThenAbrt);

class FixtureTest {
 public:
  FixtureTest() { fprintf(stderr, "<<FixtureTest::FixtureTest()>>\n"); }
  ~FixtureTest() { fprintf(stderr, "<<FixtureTest::~FixtureTest()>>\n"); }

  void NeverFails(int) {}
};
FUZZ_TEST_F(FixtureTest, NeverFails);

void RepeatedFieldHasMinimumSize(const TestProtobuf& proto) {
  if (proto.rep_b_size() < 10) std::abort();
}
FUZZ_TEST(MySuite, RepeatedFieldHasMinimumSize)
    .WithDomains(Arbitrary<TestProtobuf>().WithRepeatedBoolField(
        "rep_b", VectorOf(Arbitrary<bool>()).WithMinSize(10)));

void FailsWhenFieldI32HasNoValue(const TestProtobuf& proto) {
  if (!proto.has_i32()) std::abort();
}

FUZZ_TEST(MySuite, FailsWhenFieldI32HasNoValue)
    .WithDomains(Arbitrary<TestProtobuf>().WithInt32Field("i32",
                                                          InRange(0, 1000)));

void FailsWhenFieldI64HasValue(const TestProtobuf& proto) {
  if (proto.has_i64()) std::abort();
}
FUZZ_TEST(MySuite, FailsWhenFieldI64HasValue)
    .WithDomains(Arbitrary<TestProtobuf>().WithInt64FieldUnset("i64"));

void FailsWhenFieldDoubleHasNoValue(const TestProtobuf& proto) {
  if (!proto.has_d()) std::abort();
}

FUZZ_TEST(MySuite, FailsWhenFieldDoubleHasNoValue)
    .WithDomains(Arbitrary<TestProtobuf>().WithDoubleFieldAlwaysSet(
        "d", InRange(0., 1000.)));

void FailsWhenSubprotoIsNull(const TestProtobuf& proto) {
  if (!proto.has_subproto()) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, FailsWhenSubprotoIsNull)
    .WithDomains(
        Arbitrary<TestProtobuf>().WithProtobufFieldAlwaysSet("subproto"));

void FailsWhenSubprotoFieldsAreSet(const TestProtobuf& proto) {
  if (proto.has_subproto() || proto.rep_subproto_size() > 0) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, FailsWhenSubprotoFieldsAreSet)
    .WithDomains(Arbitrary<TestProtobuf>()
                     .WithProtobufFieldUnset("subproto")
                     .WithRepeatedProtobufField(
                         "rep_subproto", VectorOf(Arbitrary<TestSubProtobuf>())
                                             .WithMaxSize(0)));

void FailsWhenRepeatedSubprotoIsSmallOrHasAnEmptyElement(
    const TestProtobuf& proto) {
  if (proto.rep_subproto_size() < 10) {
    std::abort();
  }
  for (const auto& subproto : proto.rep_subproto()) {
    if (subproto.has_subproto_i32()) {
      std::abort();
    }
  }
}

FUZZ_TEST(MySuite, FailsWhenRepeatedSubprotoIsSmallOrHasAnEmptyElement)
    .WithDomains(Arbitrary<TestProtobuf>().WithRepeatedProtobufField(
        "rep_subproto", VectorOf(Arbitrary<TestSubProtobuf>()
                                     .WithInt32FieldUnset("subproto_i32"))
                            .WithMinSize(10)));

bool AnyNonBooleanOptionalFieldIsSet(const TestProtobuf& proto) {
  return proto.has_i32() || proto.has_u32() || proto.has_i64() ||
         proto.has_u64() || proto.has_f() || proto.has_d() || proto.has_str() ||
         proto.has_e() || proto.has_enum_one_label() ||
         proto.has_empty_message() || proto.has_subproto() ||
         proto.subproto().has_subproto_i32() ||
         absl::c_any_of(proto.rep_subproto(),
                        [](const TestSubProtobuf& sub_proto) {
                          return sub_proto.has_subproto_i32();
                        });
}

void FailsWhenAnyOptionalFieldsHaveValue(const TestProtobuf& proto) {
  if (proto.has_b() || AnyNonBooleanOptionalFieldIsSet(proto)) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, FailsWhenAnyOptionalFieldsHaveValue)
    .WithDomains(Arbitrary<TestProtobuf>().WithOptionalFieldsUnset());

void FieldBIsAlwaysSetAndAllOtherOptionalFieldsAreUnset(
    const TestProtobuf& proto) {
  if (!proto.has_b() || AnyNonBooleanOptionalFieldIsSet(proto)) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, FieldBIsAlwaysSetAndAllOtherOptionalFieldsAreUnset)
    .WithDomains(Arbitrary<TestProtobuf>()
                     .WithBoolFieldAlwaysSet("b", Arbitrary<bool>())
                     .WithOptionalFieldsUnset());

void BoolFieldsAreAlwaysSetAndAllOtherOptionalFieldsAreUnset(
    const TestProtobuf& proto) {
  if (!proto.has_b() || AnyNonBooleanOptionalFieldIsSet(proto)) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, BoolFieldsAreAlwaysSetAndAllOtherOptionalFieldsAreUnset)
    .WithDomains(
        Arbitrary<TestProtobuf>()
            .WithOptionalFieldsUnset([](const FieldDescriptor* field) {
              return field->type() == FieldDescriptor::TYPE_INT32;
            })
            .WithOptionalFieldsAlwaysSet([](const FieldDescriptor* field) {
              return field->type() == FieldDescriptor::TYPE_BOOL ||
                     field->type() == FieldDescriptor::TYPE_INT32;
            })
            .WithOptionalFieldsUnset());

bool IsTestSubProtobuf(const FieldDescriptor* field) {
  return field->message_type()->full_name() ==
         "fuzztest.internal.TestSubProtobuf";
}

void FailsWhenSubprotosDontSetOptionalI32(const TestProtobuf& proto) {
  if (proto.has_subproto()) {
    if (!proto.subproto().has_subproto_i32()) {
      std::abort();
    }
  }
  for (const auto& subproto : proto.rep_subproto()) {
    if (!subproto.has_subproto_i32()) {
      std::abort();
    }
  }
}
FUZZ_TEST(MySuite, FailsWhenSubprotosDontSetOptionalI32)
    .WithDomains(Arbitrary<TestProtobuf>().WithProtobufFields(
        IsTestSubProtobuf,
        Arbitrary<TestSubProtobuf>().WithInt32FieldAlwaysSet(
            "subproto_i32", fuzztest::Arbitrary<int32_t>())));

void FailsWhenWrongDefaultProtobufDomainIsProvided(const TestProtobuf& proto) {}
FUZZ_TEST(MySuite, FailsWhenWrongDefaultProtobufDomainIsProvided)
    .WithDomains(Arbitrary<TestProtobuf>().WithProtobufFields(
        IsTestSubProtobuf, Arbitrary<TestProtobufWithRecursion>()));

void Int32FieldsRespectCustomizations(const TestProtobuf& proto) {
  if (!proto.has_i32() || proto.i32() != 1) {
    std::abort();
  }
  if (proto.rep_i32_size() == 0 || proto.rep_i32(0) != 2) {
    std::abort();
  }
  if (!proto.has_subproto()) return;
  if (proto.subproto().subproto_rep_i32_size() == 0 ||
      proto.subproto().subproto_rep_i32(0) != 2) {
    std::abort();
  }
  if (!proto.subproto().has_subproto_i32() ||
      proto.subproto().subproto_i32() != 3) {
    std::abort();
  }
}

bool IsInt32(const FieldDescriptor* field) {
  return field->type() == FieldDescriptor::TYPE_INT32;
}

bool IsNotRequired(const FieldDescriptor* field) {
  return !field->is_required();
}
bool IsRepeated(const FieldDescriptor* field) { return field->is_repeated(); }

FUZZ_TEST(MySuite, Int32FieldsRespectCustomizations)
    .WithDomains(Arbitrary<TestProtobuf>()
                     .WithInt32FieldAlwaysSet("i32", fuzztest::Just(1))
                     .WithInt32Fields(IsRepeated, fuzztest::Just(2))
                     .WithInt32Fields(IsNotRequired, fuzztest::Just(3))
                     .WithRepeatedInt32Field(
                         "rep_i32", VectorOf(fuzztest::Just(4)).WithMinSize(1))
                     .WithOptionalFieldsAlwaysSet(IsInt32)
                     .WithRepeatedFieldsMinSize(IsInt32, 1));

void FailsIfCantInitializeProto(const TestProtobufWithRecursion& proto) {}
FUZZ_TEST(MySuite, FailsIfCantInitializeProto)
    .WithDomains(Arbitrary<TestProtobufWithRecursion>()
                     .WithOptionalFieldsAlwaysSet()
                     .WithStringField("id", Arbitrary<std::string>()));

void InitializesRecursiveProtoIfInfiniteRecursivePolicyStopsPropagating(
    const TestProtobufWithRecursion& proto) {}
FUZZ_TEST(MySuite,
          InitializesRecursiveProtoIfInfiniteRecursivePolicyStopsPropagating)
    .WithDomains(Arbitrary<TestProtobufWithRecursion>()
                     .WithProtobufField(
                         "child",
                         Arbitrary<TestProtobufWithRecursion::ChildProto>()
                             .WithStringField("id", Arbitrary<std::string>()))
                     .WithOptionalFieldsAlwaysSet());

bool AreRepeatedFieldsSizesCorrect(absl::FunctionRef<bool(int)> is_size_correct,
                                   const TestProtobuf& proto) {
  return is_size_correct(proto.rep_b_size()) &&
         is_size_correct(proto.rep_i32_size()) &&
         is_size_correct(proto.rep_u32_size()) &&
         is_size_correct(proto.rep_i64_size()) &&
         is_size_correct(proto.rep_u64_size()) &&
         is_size_correct(proto.rep_f_size()) &&
         is_size_correct(proto.rep_d_size()) &&
         is_size_correct(proto.rep_str_size()) &&
         is_size_correct(proto.rep_e_size()) &&
         is_size_correct(proto.rep_subproto_size()) &&
         absl::c_all_of(
             proto.rep_subproto(),
             [is_size_correct](const TestSubProtobuf& sub_proto) {
               return is_size_correct(sub_proto.subproto_rep_i32_size());
             });
}

void FailsIfRepeatedFieldsDontHaveTheMinimumSize(const TestProtobuf& proto) {
  if (!AreRepeatedFieldsSizesCorrect([](int size) { return size >= 10; },
                                     proto)) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, FailsIfRepeatedFieldsDontHaveTheMinimumSize)
    .WithDomains(Arbitrary<TestProtobuf>().WithRepeatedFieldsMinSize(10));

void FailsIfRepeatedFieldsDontHaveTheMaximumSize(const TestProtobuf& proto) {
  if (!AreRepeatedFieldsSizesCorrect([](int size) { return size <= 10; },
                                     proto)) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, FailsIfRepeatedFieldsDontHaveTheMaximumSize)
    .WithDomains(Arbitrary<TestProtobuf>().WithRepeatedFieldsMaxSize(10));

fuzztest::Domain<int> IgnoreZero(fuzztest::Domain<int> d) {
  return fuzztest::Filter([](int x) { return x != 0; }, std::move(d));
}

void FailsIfRepeatedEnumsHaveZeroValueAndOptionalEnumHasNonZeroValue(
    const TestProtobuf& proto) {
  if (proto.has_e() && proto.e() != TestProtobuf::Label1) {
    std::abort();
  }
  for (auto e : proto.rep_e()) {
    if (e == 0) {
      std::abort();
    }
  }
}
FUZZ_TEST(MySuite,
          FailsIfRepeatedEnumsHaveZeroValueAndOptionalEnumHasNonZeroValue)
    .WithDomains(Arbitrary<TestProtobuf>()
                     .WithEnumField("e",
                                    fuzztest::Just<int>(TestProtobuf::Label1))
                     .WithEnumFieldsTransformed(IgnoreZero));

void FailsIfProtobufEnumEqualsLabel4(TestProtobuf::Enum e) {
  if (e == TestProtobuf::Enum::TestProtobuf_Enum_Label4) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, FailsIfProtobufEnumEqualsLabel4);

struct HasConstructor {
  int a = 0;
  std::string b;

  HasConstructor() = default;
  explicit HasConstructor(std::string b) : a(0), b(b) {}
  HasConstructor(int a, std::string b) : a(a), b(b) {}
};

void WorksWithStructsWithConstructors(const HasConstructor& h) {
  if (h.a == 1 && h.b == "abc") {
    std::abort();
  }
}
FUZZ_TEST(MySuite, WorksWithStructsWithConstructors)
    .WithDomains(StructOf<HasConstructor>(Just(1), Just(std::string("abc"))));

struct ContainsEmptyTuple {
  std::tuple<> a;
};

void WorksWithStructsWithEmptyTuples(const ContainsEmptyTuple&) {
  std::abort();
}
FUZZ_TEST(MySuite, WorksWithStructsWithEmptyTuples)
    .WithDomains(StructOf<ContainsEmptyTuple>());

struct LinkedList {
  LinkedList* a;
  int b = 0;
};

void WorksWithRecursiveStructs(LinkedList r) {
  if (r.b == 1) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, WorksWithRecursiveStructs)
    .WithDomains(StructOf<LinkedList>(Just<LinkedList*>(nullptr), Just(1)));

struct Empty {
  void foo() {}
};

void WorksWithEmptyStructs(Empty) { std::abort(); }
FUZZ_TEST(MySuite, WorksWithEmptyStructs).WithDomains(StructOf<Empty>());

struct ContainsEmpty {
  Empty e;
};

void WorksWithStructsWithEmptyFields(ContainsEmpty) { std::abort(); }
FUZZ_TEST(MySuite, WorksWithStructsWithEmptyFields)
    .WithDomains(StructOf<ContainsEmpty>(Just<Empty>({})));

struct Child : Empty {
  int a = 0;
  std::string b;
};

void WorksWithEmptyInheritance(const Child& c) {
  if (c.a == 0 && c.b == "abc") {
    std::abort();
  }
}
FUZZ_TEST(MySuite, WorksWithEmptyInheritance)
    .WithDomains(StructOf<Child>(Just(0), Just(std::string("abc"))));

void ArbitraryWorksWithEmptyInheritance(const Child&) { std::abort(); }
FUZZ_TEST(MySuite, ArbitraryWorksWithEmptyInheritance);

auto AnyStringPairOfSameSize(int max_size) {
  return FlatMap(
      [](int size) {
        return PairOf(Arbitrary<std::string>().WithSize(size),
                      Arbitrary<std::string>().WithSize(size));
      },
      InRange(0, max_size));
}
void FlatMapPassesWhenCorrect(const std::pair<std::string, std::string>& pair) {
  if (pair.first.size() != pair.second.size()) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, FlatMapPassesWhenCorrect)
    .WithDomains(AnyStringPairOfSameSize(10));

void FlatMapCorrectlyPrintsValues(
    const std::pair<std::string, std::string>& pair) {
  if (pair.first != pair.second) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, FlatMapCorrectlyPrintsValues)
    .WithDomains(FlatMap(
        [](int size) {
          return PairOf(StringOf(Just('A')).WithSize(size),
                        StringOf(Just('B')).WithSize(size));
        },
        Just(3)));

}  // namespace
