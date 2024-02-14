// Copyright 2024 Google LLC
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

#include <cstdint>
#include <cstdlib>
#include <limits>
#include <vector>

#include "./fuzztest/fuzztest.h"
#include "./fuzztest/internal/test_protobuf.pb.h"

namespace {

using fuzztest::internal::CalculatorExpression;
using fuzztest::internal::FoodMachineProcedure;
using fuzztest::internal::RoboCourier560Plan;
using fuzztest::internal::SingleBytesField;
using fuzztest::internal::TestProtobuf;

void BytesSummingToMagicValue(const SingleBytesField& input) {
  char sum = 0;
  for (const char c : input.data()) {
    sum += c;
  }
  if (sum == 0x72) {
    std::abort();
  }
}
FUZZ_TEST(ProtoPuzzles, BytesSummingToMagicValue);

void BytesSummingToMagicValueWithOverloadedProto(
    const SingleBytesField& input) {
  char sum = 0;
  for (const char c : input.data()) {
    sum += c;
  }
  if (sum == 0x72) {
    std::abort();
  }
}
FUZZ_TEST(ProtoPuzzles, BytesSummingToMagicValueWithOverloadedProto);

void PrefixBytesSummingToMagicValue(const SingleBytesField& input) {
  if (input.data().size() < 2) {
    return;
  }
  if (input.data()[0] + input.data()[1] == 0x72) {
    std::abort();
  }
}
FUZZ_TEST(ProtoPuzzles, PrefixBytesSummingToMagicValue);

void PrefixBytesSummingToMagicValueWithOverloadedProto(
    const TestProtobuf& input) {
  if (input.str().size() < 2) {
    return;
  }
  if (input.str()[0] + input.str()[1] == 0x72) {
    std::abort();
  }
}
FUZZ_TEST(ProtoPuzzles, PrefixBytesSummingToMagicValueWithOverloadedProto);

void PrefixIsMagicValue(const SingleBytesField& input) {
  if (input.data().size() < 2) {
    return;
  }
  if (input.data()[0] + input.data()[1] == 0x72) {
    std::abort();
  }
}
FUZZ_TEST(ProtoPuzzles, PrefixIsMagicValue);

void PrefixIsMagicValueWithOverloadedProto(const TestProtobuf& input) {
  if (input.str().size() < 2) {
    return;
  }
  if (input.str()[0] + input.str()[1] == 0x72) {
    std::abort();
  }
}
FUZZ_TEST(ProtoPuzzles, PrefixIsMagicValueWithOverloadedProto);

void ContainsCharactersSpecifiedAtStartOfString(const SingleBytesField& input) {
  if (input.data().size() < 2) {
    return;
  }
  char quantity = input.data()[0];
  char to_find = input.data()[1];

  if (to_find == 0) {
    return;
  }

  char num_found = 0;
  for (int i = 2; i < input.data().size(); ++i) {
    if (input.data()[i] == to_find) {
      num_found++;
    }
  }
  if (num_found == quantity) {
    abort();
  }
}
FUZZ_TEST(ProtoPuzzles, ContainsCharactersSpecifiedAtStartOfString);

void ContainsCharactersSpecifiedAtStartOfStringWithOverloadedProto(
    const TestProtobuf& input) {
  if (input.str().size() < 2) {
    return;
  }
  char quantity = input.str()[0];
  char to_find = input.str()[1];

  if (to_find == 0) {
    return;
  }

  char num_found = 0;
  for (int i = 2; i < input.str().size(); ++i) {
    if (input.str()[i] == to_find) {
      num_found++;
    }
  }
  if (num_found == quantity) {
    // [Hint] Reachable if the second character of the string appears the same
    // number of times as the first character of the string within the suffix.
    std::abort();
  }
}
FUZZ_TEST(ProtoPuzzles,
          ContainsCharactersSpecifiedAtStartOfStringWithOverloadedProto);

enum class FoodMachineState {
  kOff,
  kWarm,
  kFoodInserted,
  kFoodPrepared,
  kFoodCooked,
};

FoodMachineState UpdateFoodMachineState(
    const FoodMachineProcedure::Action& action, FoodMachineState curr_state,
    std::vector<std::string>& machine_contents) {
  switch (action.type()) {
    case FoodMachineProcedure::Action::TYPE_UNSPECIFIED:
      return curr_state;
    case FoodMachineProcedure::Action::WARMUP:
      if (curr_state == FoodMachineState::kOff) {
        return FoodMachineState::kWarm;
      }
      return curr_state;
    case FoodMachineProcedure::Action::INSERT_RAW_MATERIALS:
      if (curr_state == FoodMachineState::kWarm) {
        if (action.materials().empty()) {
          machine_contents.push_back("atmosphere");
        }
        for (const std::string& material : action.materials()) {
          machine_contents.push_back(material);
        }
        return FoodMachineState::kFoodInserted;
      }
      return curr_state;
    case FoodMachineProcedure::Action::PREPARE_RAW_MATERIALS:
      if (curr_state == FoodMachineState::kFoodInserted) {
        return FoodMachineState::kFoodPrepared;
      }
      return curr_state;
    case FoodMachineProcedure::Action::COOK:
      if (curr_state == FoodMachineState::kFoodPrepared) {
        return FoodMachineState::kFoodCooked;
      }
      return curr_state;
    case FoodMachineProcedure::Action::PLATE:
      if (curr_state == FoodMachineState::kFoodCooked) {
        if (machine_contents.empty()) std::abort();
        machine_contents.clear();
        return FoodMachineState::kOff;
      }
      return curr_state;
    case FoodMachineProcedure::Action::EMERGENCY_STOP:
      // Eject any already cooked food in case it can help with the current
      // emergency.
      if (curr_state == FoodMachineState::kFoodCooked) {
        machine_contents.clear();
      }
      return curr_state;
  }
}

void RunFoodMachine(const FoodMachineProcedure& procedure) {
  std::vector<std::string> machine_contents;
  FoodMachineState state = FoodMachineState::kOff;
  for (const FoodMachineProcedure::Action& action : procedure.actions()) {
    state = UpdateFoodMachineState(action, state, machine_contents);
    if (state == FoodMachineState::kOff) {
      return;
    }
  }
}
FUZZ_TEST(ProtoPuzzles, RunFoodMachine);

int EvalCalculatorExpressionHelper(const CalculatorExpression& expression) {
  switch (expression.type()) {
    case CalculatorExpression::TYPE_UNSPECIFIED: {
      return 0;
    }
    case CalculatorExpression::ADD: {
      return EvalCalculatorExpressionHelper(expression.left()) +
             EvalCalculatorExpressionHelper(expression.right());
    }
    case CalculatorExpression::SUB: {
      return EvalCalculatorExpressionHelper(expression.left()) -
             EvalCalculatorExpressionHelper(expression.right());
    }
    case CalculatorExpression::MUL: {
      return EvalCalculatorExpressionHelper(expression.left()) *
             EvalCalculatorExpressionHelper(expression.right());
    }
    case CalculatorExpression::DIV: {
      int left = EvalCalculatorExpressionHelper(expression.left());
      int right = EvalCalculatorExpressionHelper(expression.right());
      if (right == 0) {
        return std::numeric_limits<int>::max();
      }
      return left / right;
    }
    case CalculatorExpression::VALUE: {
      return expression.value();
    }
  }
}
void EvalCalculatorExpression(const CalculatorExpression& expression) {
  EvalCalculatorExpressionHelper(expression);
}
FUZZ_TEST(ProtoPuzzles, EvalCalculatorExpression);

struct DeliveryResult {
  std::string location_name;
  std::string location_address;
  std::string mail_name;
  std::string mail_content;
};

std::vector<DeliveryResult> RoboCourierRun(const RoboCourier560Plan& plan) {
  std::vector<DeliveryResult> results;
  for (const RoboCourier560Plan::Mail& mail : plan.mail()) {
    std::string name = mail.name();
    if (mail.name().empty()) {
      continue;
    }
    if (mail.address().empty()) {
      continue;
    }
    if (plan.extra_actions().contains(mail.address())) {
      const RoboCourier560Plan::ExtraAction extra_action =
          plan.extra_actions().at(mail.address());
      switch (extra_action.type()) {
        case RoboCourier560Plan::ExtraAction::TYPE_UNSPECIFIED: {
          break;
        }
        case RoboCourier560Plan::ExtraAction::CHANGE_NAME: {
          name = extra_action.content();
          break;
        }
        case RoboCourier560Plan::ExtraAction::POST_NOTICE: {
          results.push_back(
              DeliveryResult{.location_name = name,
                             .location_address = mail.address(),
                             .mail_name = mail.name(),
                             .mail_content = extra_action.content()});
          break;
        }
      }
    }
    results.push_back(DeliveryResult{.location_name = name,
                                     .location_address = mail.address(),
                                     .mail_name = mail.name(),
                                     .mail_content = mail.content()});
  }
  return results;
}

void RunRoboCourier560(const RoboCourier560Plan& plan) {
  const std::vector<DeliveryResult> results = RoboCourierRun(plan);

  for (const DeliveryResult& result : results) {
    if (result.location_name != result.mail_name) {
      // [Hint] Mail delivered to the wrong name. Can happen if mail is
      // delivered at before a `CHANGE_NAME` action.
      std::abort();
    }
  }
}
FUZZ_TEST(ProtoPuzzles, RunRoboCourier560);

void IntegerConditionsOnTestProtobufLevel00(const TestProtobuf& input) {
  int64_t integer_result;
  if (input.b()) {
    if (__builtin_add_overflow(input.i32(), input.i64(), &integer_result)) {
      return;  // [Hint] Overflow detected
    }
  } else {
    if (__builtin_sub_overflow(input.i32(), input.i64(), &integer_result)) {
      return;  // [Hint] Overflow detected
    }
  }
  if (integer_result < 1239291904) {
    return;
  }

  if (input.rep_b().empty()) {
    return;
  }
  uint64_t unsigned_result;
  if (input.rep_b()[0]) {
    unsigned_result = input.u32() + input.u64() + input.rep_b()[0];
  } else {
    unsigned_result = input.u32() - input.u64() - input.rep_b()[0];
  }
  if (unsigned_result != 2000) {
    return;
  }
  // [Hint] Reachable if all of the early returns above are not taken.
  std::abort();
}
FUZZ_TEST(ProtoPuzzles, IntegerConditionsOnTestProtobufLevel00);

void IntegerConditionsOnTestProtobufLevel01(const TestProtobuf& input) {
  int64_t integer_result;
  if (input.b()) {
    if (__builtin_add_overflow(input.i32(), input.i64(), &integer_result)) {
      return;  // [Hint] Overflow detected
    }
  } else {
    if (__builtin_sub_overflow(input.i32(), input.i64(), &integer_result)) {
      return;  // [Hint] Overflow detected
    }
  }
  if (integer_result < 1239291904) {
    return;
  }

  if (input.rep_b().empty()) {
    return;
  }
  if (input.rep_b().size() < 5) {
    return;
  }
  bool flip = false;
  uint32_t num_trues = 0;
  for (const bool& b : input.rep_b()) {
    flip += b;
    num_trues += b;
  }
  uint64_t unsigned_result;
  if (flip) {
    unsigned_result = input.u32() + input.u64() + num_trues;
  } else {
    unsigned_result = input.u32() - input.u64() + num_trues;
  }
  if (unsigned_result != 2000) {
    return;
  }
  // [Hint] reachable if none of the early returns above are taken.
  std::abort();
}
FUZZ_TEST(ProtoPuzzles, IntegerConditionsOnTestProtobufLevel01);

}  // namespace
