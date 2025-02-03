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

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "./fuzztest/fuzztest.h"
#include "absl/algorithm/container.h"
#include "absl/functional/function_ref.h"
#include "absl/strings/match.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/test_protobuf.pb.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/message.h"
#include "google/protobuf/message_lite.h"

namespace {

using ::fuzztest::Arbitrary;
using ::fuzztest::FlatMap;
using ::fuzztest::InRange;
using ::fuzztest::Just;
using ::fuzztest::OptionalOf;
using ::fuzztest::PairOf;
using ::fuzztest::StringOf;
using ::fuzztest::StructOf;
using ::fuzztest::TupleOf;
using ::fuzztest::VectorOf;
using ::fuzztest::internal::ProtoExtender;
using ::fuzztest::internal::SingleInt32Field;
using ::fuzztest::internal::TestProtobuf;
using ::fuzztest::internal::TestProtobufWithExtension;
using ::fuzztest::internal::TestProtobufWithRecursion;
using ::fuzztest::internal::TestProtobufWithRequired;
using ::fuzztest::internal::TestSubProtobuf;
using ::google::protobuf::FieldDescriptor;

bool print_target_run_message_once = []() {
  fputs("FuzzTest functional test target run\n", stderr);
  return true;
}();

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
  absl::FPrintF(stderr, "==<<Saw size=%zu>>==\n", v.size());
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
  absl::FPrintF(stderr, "Takes a very long time for one iter...\n");
}
FUZZ_TEST(MySuite, OneIterationTakesTooMuchTime);

auto SeedInputIsUsed(const std::vector<int>& s) {
  if (s == std::vector<int>{0x90091E, 0x15, 0xC001}) std::abort();
}
FUZZ_TEST(MySuite, SeedInputIsUsed).WithSeeds({{{0x90091E, 0x15, 0xC001}}});

void LongInput(const std::vector<char>& input) {
  if (input.size() == 5000) std::abort();
}
FUZZ_TEST(MySuite, LongInput)
    .WithDomains(Arbitrary<std::vector<char>>().WithMaxSize(5000))
    .WithSeeds({std::vector(5000, 'A')});

TestProtobuf GetMagicalProto() {
  TestProtobuf result;
  result.add_rep_subproto()->set_subproto_i32(9439518);
  return result;
}

auto SeedInputIsUsedInProtobufsWithInternalMappings(const TestProtobuf& proto) {
  if (proto.DebugString() == GetMagicalProto().DebugString()) std::abort();
}
FUZZ_TEST(MySuite, SeedInputIsUsedInProtobufsWithInternalMappings)
    .WithDomains(Arbitrary<TestProtobuf>().WithRepeatedProtobufField(
        "rep_subproto", VectorOf(Arbitrary<TestSubProtobuf>()).WithMinSize(1)))
    .WithSeeds({GetMagicalProto()});

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
    absl::FPrintF(stderr, "Uses proto extensions!\n");
    std::abort();
  }
}

FUZZ_TEST(MySuite, CheckProtoExtensions).WithSeeds(ProtoSeeds());

void TargetPrintSomethingThenAbrt(int a) {
  absl::FPrintF(stdout, "Hello World from target stdout\n");
  absl::FPrintF(stderr, "Hello World from target stderr\n");
  std::fflush(stdout);
  std::fflush(stderr);
  if (a > 42) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, TargetPrintSomethingThenAbrt);

class FixtureTest {
 public:
  FixtureTest() { absl::FPrintF(stderr, "<<FixtureTest::FixtureTest()>>\n"); }
  ~FixtureTest() { absl::FPrintF(stderr, "<<FixtureTest::~FixtureTest()>>\n"); }

  void NeverFails(int) {}
};
FUZZ_TEST_F(FixtureTest, NeverFails);

void RepeatedFieldHasMinimumSize(const TestProtobuf& proto) {
  if (proto.rep_b_size() < 10) std::abort();
}
FUZZ_TEST(MySuite, RepeatedFieldHasMinimumSize)
    .WithDomains(Arbitrary<TestProtobuf>().WithRepeatedBoolField(
        "rep_b", VectorOf(Arbitrary<bool>()).WithMinSize(10)));

void FailsWhenFieldI32HasNoValue(const SingleInt32Field& proto) {
  if (!proto.has_i32()) std::abort();
}

FUZZ_TEST(MySuite, FailsWhenFieldI32HasNoValue)
    .WithDomains(
        Arbitrary<SingleInt32Field>().WithInt32Field("i32", InRange(0, 1000)));

void FailsWhenFieldI64HasValue(const TestProtobuf& proto) {
  if (proto.has_i64()) std::abort();
}
FUZZ_TEST(MySuite, FailsWhenFieldI64HasValue)
    .WithDomains(Arbitrary<TestProtobuf>().WithInt64FieldUnset("i64"));

void FailsWhenFieldsOfTypeDoubleHasNoValue(const TestProtobuf& proto) {
  static constexpr double kTolerance = 0.01;
  if (!proto.has_d()) std::abort();
  if (proto.d() > 10 + kTolerance || proto.d() < 0 - kTolerance) std::abort();
  if (proto.rep_d_size() == 0) std::abort();
  for (const auto& d : proto.rep_d()) {
    if (d > 10 + kTolerance || d < 0 - kTolerance) std::abort();
  }
}

FUZZ_TEST(MySuite, FailsWhenFieldsOfTypeDoubleHasNoValue)
    .WithDomains(Arbitrary<TestProtobuf>()
                     .WithDoubleFieldAlwaysSet("d", InRange(0., 10.))
                     .WithDoubleFieldAlwaysSet("rep_d", InRange(0., 10.)));

bool IsUInt32(const FieldDescriptor* field) {
  return field->type() == FieldDescriptor::TYPE_UINT32;
}
bool IsUInt64(const FieldDescriptor* field) {
  return field->type() == FieldDescriptor::TYPE_UINT64;
}
void FailsWhen64IntegralFieldsHaveValues(const TestProtobuf& proto) {
  if (proto.has_i64()) std::abort();
  if (proto.rep_i64_size() > 0) std::abort();
  if (proto.has_u64()) std::abort();
  if (proto.rep_u64_size() > 0) std::abort();
  if (proto.has_u32()) std::abort();
  if (proto.rep_u32_size() > 0) std::abort();
}
FUZZ_TEST(MySuite, FailsWhen64IntegralFieldsHaveValues)
    .WithDomains(Arbitrary<TestProtobuf>()
                     .WithFieldsUnset(IsUInt32)
                     .WithOptionalFieldsUnset(IsUInt64)
                     .WithRepeatedFieldsUnset(IsUInt64)
                     .WithFieldUnset("i64")
                     .WithFieldUnset("rep_i64"));

void FailsWhen64IntegralFieldsHaveNoValues(const TestProtobuf& proto) {
  if (!proto.has_i64()) std::abort();
  if (proto.rep_i64_size() == 0) std::abort();
  if (!proto.has_u64()) std::abort();
  if (proto.rep_u64_size() == 0) std::abort();
  if (!proto.has_u32()) std::abort();
  if (proto.rep_u32_size() == 0) std::abort();
}
FUZZ_TEST(MySuite, FailsWhen64IntegralFieldsHaveNoValues)
    .WithDomains(Arbitrary<TestProtobuf>()
                     .WithFieldsAlwaysSet(IsUInt32)
                     .WithOptionalFieldsAlwaysSet(IsUInt64)
                     .WithRepeatedFieldsAlwaysSet(IsUInt64)
                     .WithFieldAlwaysSet("i64")
                     .WithFieldAlwaysSet("rep_i64"));

void FailsWhenRequiredInt32FieldHasNoValue(
    const TestProtobufWithRequired& proto) {
  if (!proto.has_req_i32()) std::abort();
}

FUZZ_TEST(MySuite, FailsWhenRequiredInt32FieldHasNoValue)
    .WithDomains(Arbitrary<TestProtobufWithRequired>().WithInt32Field(
        "req_i32", InRange(0, 1000)));

void FailsWhenRequiredEnumFieldHasNoValue(
    const TestProtobufWithRequired& proto) {
  if (!proto.has_req_e()) std::abort();
}

FUZZ_TEST(MySuite, FailsWhenRequiredEnumFieldHasNoValue)
    .WithDomains(
        Arbitrary<TestProtobufWithRequired>().WithEnumFieldUnset("req_e"));

void FailsWhenOptionalFieldU32HasNoValue(const TestProtobuf& proto) {
  if (!proto.has_u32()) std::abort();
}
FUZZ_TEST(MySuite, FailsWhenOptionalFieldU32HasNoValue)
    .WithDomains(Arbitrary<TestProtobuf>().WithOptionalUInt32Field(
        "u32", OptionalOf(InRange(0u, 1000u))));

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
    .WithDomains(
        Arbitrary<TestProtobuf>()
            .WithOptionalProtobufField("subproto",
                                       fuzztest::NullOpt<TestSubProtobuf>())
            .WithRepeatedProtobufField(
                "rep_subproto",
                VectorOf(Arbitrary<TestSubProtobuf>()).WithMaxSize(0)));

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

void FailsWhenAnyOptionalFieldsHaveValueButNotFieldsWithOverwrittenDomain(
    const TestProtobuf& proto) {
  if (!proto.has_b() || AnyNonBooleanOptionalFieldIsSet(proto)) {
    std::abort();
  }
}
FUZZ_TEST(MySuite,
          FailsWhenAnyOptionalFieldsHaveValueButNotFieldsWithOverwrittenDomain)
    .WithDomains(Arbitrary<TestProtobuf>()
                     .WithOptionalFieldsUnset()
                     .WithBoolFieldAlwaysSet("b", Arbitrary<bool>()));

void FailsWhenAnyOptionalFieldsHaveValueButNotFieldsWithOverwrittenPolicy(
    const TestProtobuf& proto) {
  if (!proto.has_b() || AnyNonBooleanOptionalFieldIsSet(proto)) {
    std::abort();
  }
}
FUZZ_TEST(MySuite,
          FailsWhenAnyOptionalFieldsHaveValueButNotFieldsWithOverwrittenPolicy)
    .WithDomains(
        Arbitrary<TestProtobuf>()
            .WithOptionalFieldsUnset()
            .WithOptionalFieldsAlwaysSet([](const FieldDescriptor* field) {
              return field->type() == FieldDescriptor::TYPE_BOOL ||
                     field->type() == FieldDescriptor::TYPE_INT32;
            })
            .WithOptionalFieldsUnset([](const FieldDescriptor* field) {
              return field->type() == FieldDescriptor::TYPE_INT32;
            }));

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

void FailsWhenWrongDefaultProtobufDomainIsProvided(const TestProtobuf& proto) {
  (void)proto.subproto();
}
FUZZ_TEST(MySuite, FailsWhenWrongDefaultProtobufDomainIsProvided)
    .WithDomains(Arbitrary<TestProtobuf>().WithProtobufFields(
        IsTestSubProtobuf, Arbitrary<TestProtobufWithRecursion>()));

void FailsWhenI32FieldValuesDontRespectAllPolicies(const TestProtobuf& proto) {
  if (!proto.has_i32() || proto.i32() != 1) {
    std::abort();
  }
  if (proto.rep_i32_size() == 0 || proto.rep_i32(0) != 2) {
    std::abort();
  }
  if (!proto.has_subproto()) return;
  if (proto.subproto().subproto_rep_i32_size() == 0 ||
      proto.subproto().subproto_rep_i32(0) != 4) {
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
bool IsInSubproto(const FieldDescriptor* field) {
  return absl::StrContains(field->name(), "subproto");
}

FUZZ_TEST(MySuite, FailsWhenI32FieldValuesDontRespectAllPolicies)
    .WithDomains(Arbitrary<TestProtobuf>()
                     .WithOptionalFieldsAlwaysSet(IsInt32)
                     .WithRepeatedFieldsMinSize(IsInt32, 1)
                     .WithInt32Fields(IsNotRequired, fuzztest::Just(3))
                     .WithRepeatedInt32Fields(fuzztest::Just(2))
                     .WithRepeatedInt32Fields(IsInSubproto, fuzztest::Just(4))
                     .WithInt32Field("i32", fuzztest::Just(1)));

bool IsChildId(const FieldDescriptor* field) {
  return field->name() == "child_id";
}

bool IsParent(const FieldDescriptor* field) {
  return absl::StrContains(field->name(), "parent");
}

bool IsParent1(const FieldDescriptor* field) {
  return absl::StrContains(field->name(), "parent1");
}

void FailsIfCantInitializeProto(const TestProtobufWithRecursion& proto) {}
FUZZ_TEST(MySuite, FailsIfCantInitializeProto)
    .WithDomains(Arbitrary<TestProtobufWithRecursion>()
                     .WithOptionalFieldsAlwaysSet()
                     .WithFieldsUnset(IsChildId)
                     .WithFieldUnset("id"));

void FailIfRequiredRecursiveFieldsAreUnset(
    const TestProtobufWithRecursion& proto) {
  if (proto.has_child() && !proto.child().has_parent1()) std::abort();
}
FUZZ_TEST(MySuite, FailIfRequiredRecursiveFieldsAreUnset)
    .WithDomains(
        Arbitrary<TestProtobufWithRecursion>().WithFieldsAlwaysSet(IsParent1));

void InitializesRecursiveProtoIfInfiniteRecursivePolicyIsOverwritten(
    const TestProtobufWithRecursion& proto) {}
FUZZ_TEST(MySuite,
          InitializesRecursiveProtoIfInfiniteRecursivePolicyIsOverwritten)
    .WithDomains(Arbitrary<TestProtobufWithRecursion>()
                     .WithOptionalFieldsAlwaysSet()
                     .WithOptionalFieldsUnset(IsInt32)
                     .WithOneofAlwaysSet("type")
                     .WithFieldUnset("ext")
                     .WithProtobufField(
                         "child",
                         Arbitrary<TestProtobufWithRecursion::ChildProto>()
                             .WithFieldsAlwaysSet()
                             .WithProtobufFields(
                                 IsParent,
                                 Arbitrary<TestProtobufWithRecursion>())));

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
  if (proto.rep_b_size() < 20) std::abort();
}
FUZZ_TEST(MySuite, FailsIfRepeatedFieldsDontHaveTheMinimumSize)
    .WithDomains(Arbitrary<TestProtobuf>()
                     .WithRepeatedFieldsMinSize(10)
                     .WithRepeatedFieldMinSize("rep_b", 20));

void FailsIfRepeatedFieldsDontHaveTheMaximumSize(const TestProtobuf& proto) {
  if (!AreRepeatedFieldsSizesCorrect([](int size) { return size <= 10; },
                                     proto)) {
    std::abort();
  }
  if (proto.rep_b_size() > 5) std::abort();
}
FUZZ_TEST(MySuite, FailsIfRepeatedFieldsDontHaveTheMaximumSize)
    .WithDomains(Arbitrary<TestProtobuf>()
                     .WithRepeatedFieldsMaxSize(10)
                     .WithRepeatedFieldMaxSize("rep_b", 5));

void FailsToInitializeIfRepeatedFieldsSizeRangeIsInvalid(
    const TestProtobuf& proto) {}
FUZZ_TEST(MySuite, FailsToInitializeIfRepeatedFieldsSizeRangeIsInvalid)
    .WithDomains(Arbitrary<TestProtobuf>()
                     .WithRepeatedFieldsMaxSize(10)
                     .WithRepeatedFieldsMinSize(IsInt32, 11));

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
                     .WithEnumFieldsTransformed(IgnoreZero)
                     .WithEnumField("e",
                                    fuzztest::Just<int>(TestProtobuf::Label1)));

void FailsWhenOneofFieldDoesntHaveOneofValue(const TestProtobuf& proto) {
  if (!proto.has_oneof_i32() && !proto.has_oneof_i64()) {
    std::abort();
  }
  if (proto.has_oneof_i64() && proto.oneof_i64() != 1) {
    std::abort();
  }
}
FUZZ_TEST(MySuite, FailsWhenOneofFieldDoesntHaveOneofValue)
    .WithDomains(Arbitrary<TestProtobuf>()
                     .WithOneofAlwaysSet("oneof_field")
                     .WithFieldUnset("oneof_u32")
                     .WithInt64Field("oneof_i64", fuzztest::Just(int64_t{1})));

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

void FailsWhenI32IsSet(std::unique_ptr<google::protobuf::Message> m) {
  if (m->GetDescriptor()->full_name() != "fuzztest.internal.SingleInt32Field") {
    return;
  }
  const auto& proto =
      google::protobuf::DynamicCastMessage<fuzztest::internal::SingleInt32Field>(*m);
  if (proto.has_i32()) {
    absl::FPrintF(stderr, "The field i32 is set!\n");
    std::abort();
  }
}
FUZZ_TEST(MySuite, FailsWhenI32IsSet).WithDomains(fuzztest::ProtobufOf([]() {
  return &fuzztest::internal::SingleInt32Field::default_instance();
}));

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

void UnpacksTupleOfOne(const std::string&) { std::abort(); }
FUZZ_TEST(MySuite, UnpacksTupleOfOne)
    .WithDomains(TupleOf(Arbitrary<std::string>()));

void UnpacksTupleOfThree(const std::string&, int, int) { std::abort(); }
FUZZ_TEST(MySuite, UnpacksTupleOfThree)
    .WithDomains(TupleOf(Arbitrary<std::string>(), Arbitrary<int>(),
                         Arbitrary<int>()));

void UnpacksTupleContainingTuple(std::tuple<std::string, int>, std::string,
                                 int) {
  std::abort();
}
FUZZ_TEST(MySuite, UnpacksTupleContainingTuple)
    .WithDomains(TupleOf(TupleOf(Arbitrary<std::string>(), Arbitrary<int>()),
                         Arbitrary<std::string>(), Arbitrary<int>()));

int DataDependentStackOverflowImpl(const std::string& s, int i) {
  // Use a volatile to prevent the compiler from inlining the recursion.
  volatile auto f = DataDependentStackOverflowImpl;
  return i < s.size() ? 1 + f(s, i + 1) : 0;
}

void DataDependentStackOverflow(const std::string& s) {
  DataDependentStackOverflowImpl(s, 0);
}
FUZZ_TEST(MySuite, DataDependentStackOverflow)
    .WithDomains(fuzztest::Arbitrary<std::string>().WithSize(100000));

class AlternateSignalStackFixture {
 public:
  AlternateSignalStackFixture() {
    struct sigaction new_sigact = {};
    sigemptyset(&new_sigact.sa_mask);
    new_sigact.sa_sigaction = [](auto...) {
      ++dummy_to_trigger_cmp_in_handler;
      if (dummy_to_trigger_cmp_in_handler > 100) {
        dummy_to_trigger_cmp_in_handler = 1;
      }
    };

    // We make use of the SA_ONSTACK flag to have a separate stack for the
    // signal. This is critical to exercise the condition this test is testing,
    // where the callbacks from the signal handler happen in a separate stack.
    new_sigact.sa_flags = SA_SIGINFO | SA_ONSTACK;

    FUZZTEST_INTERNAL_CHECK(sigaction(SIGUSR1, &new_sigact, nullptr) == 0,
                            errno);
    stack_t test_stack = {};
    test_stack.ss_size = 1 << 20;
    test_stack.ss_sp = malloc(test_stack.ss_size);
    FUZZTEST_INTERNAL_CHECK(sigaltstack(&test_stack, &old_stack) == 0, errno);
  }

  void StackCalculationWorksWithAlternateStackForSignalHandlers(int i) {
    dummy_to_trigger_cmp_in_handler = 0;
    // Raise the signal to get the handler running.
    // If the stack calculations are done correctly, that code will not trigger
    // "stack overflow" detection and we will continue here.
    raise(SIGUSR1);
    // Just make sure the signal handler ran.
    FUZZTEST_INTERNAL_CHECK(dummy_to_trigger_cmp_in_handler != 0, "");

    if (i == 123456789) {
      std::abort();
    }
  }

  ~AlternateSignalStackFixture() {
    stack_t test_stack = {};
    // Resume to the old signal stack.
    FUZZTEST_INTERNAL_CHECK(sigaltstack(&old_stack, &test_stack) == 0, errno);
    free(test_stack.ss_sp);
  }

 private:
  stack_t old_stack = {};
  static size_t dummy_to_trigger_cmp_in_handler;
};
size_t AlternateSignalStackFixture::dummy_to_trigger_cmp_in_handler = 0;
FUZZ_TEST_F(AlternateSignalStackFixture,
            StackCalculationWorksWithAlternateStackForSignalHandlers);

void DetectRegressionAndCoverageInputs(const std::string& input) {
  if (absl::StartsWith(input, "regression")) {
    std::cerr << "regression input detected: " << input << std::endl;
  }
  if (absl::StartsWith(input, "coverage")) {
    std::cerr << "coverage input detected: " << input << std::endl;
    // Sleep for the first coverage input for depleting the replay time budget.
    static bool first_input = true;
    if (first_input) {
      first_input = false;
      absl::SleepFor(absl::Seconds(2));
    }
  }
}
FUZZ_TEST(MySuite, DetectRegressionAndCoverageInputs);

void CrashOnCrashingInput(const std::string& input) {
  if (absl::StartsWith(input, "crashing")) std::abort();
}
FUZZ_TEST(MySuite, CrashOnCrashingInput);

void Sleep(unsigned int x) { absl::SleepFor(absl::Seconds(x)); }
FUZZ_TEST(MySuite, Sleep).WithDomains(Just(10));

void LargeHeapAllocation(size_t allocation_size) {
  static volatile char byte_sink = 0;
  auto* ptr = static_cast<char*>(malloc(allocation_size));
  memset(ptr, 42, allocation_size);
  byte_sink = ptr[0];
  free(ptr);
}
FUZZ_TEST(MySuite, LargeHeapAllocation)
    .WithDomains(Just(
        // 1 GiB
        1ULL << 30));

// A fuzz test that is expected to accept and skip some inputs before hitting
// the crash.
void SkipInputs(uint32_t input) {
  static bool skipped_input = false;
  static bool accepted_input = false;
  // Crash only when `input` is 123456789.
  if (input != 123456789) {
    // The condition below should have enough chance to either pass or not.
    //
    // Note that we want the input to here be accepted at least once so that the
    // fuzzing engine can learn about the branch above.
    if (input % 7 % 2 == 0) {
      if (!skipped_input) {
        skipped_input = true;
        std::cerr << "Skipped input" << std::endl;
      }
      fuzztest::SkipTestsOrCurrentInput();
      return;
    }
    if (!accepted_input) accepted_input = true;
    return;
  }
  // This introduces statefulness which is undesired in real fuzz tests, but
  // here it makes it more reliable for functional testing.
  if (skipped_input && accepted_input) {
    std::abort();
  }
}
// Due to the limitation of the fuzzing engine, there must be an accepted input
// when initializing the corpus for fuzzing. So we provide one.
FUZZ_TEST(MySuite, SkipInputs).WithSeeds({1});

class FaultySetupTest {
 public:
  FaultySetupTest() { std::abort(); }
  void NoOp(int) {}
};
FUZZ_TEST_F(FaultySetupTest, NoOp);

}  // namespace
