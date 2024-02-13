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

#include <cstdlib>
#include <vector>

#include "./fuzztest/fuzztest.h"
#include "./fuzztest/internal/test_protobuf.pb.h"

namespace {

using fuzztest::internal::FoodMachineProcedure;
using fuzztest::internal::TestProtobuf;

void BytesSummingToMagicValue(const TestProtobuf& input) {
  char sum = 0;
  for (const char c : input.str()) {
    sum += c;
  }
  if (sum == 0x72) {
    std::abort();
  }
}
FUZZ_TEST(ProtoPuzzles, BytesSummingToMagicValue);

void PrefixBytesSummingToMagicValue(const TestProtobuf& input) {
  if (input.str().size() < 2) {
    return;
  }
  if (input.str()[0] + input.str()[1] == 0x72) {
    std::abort();
  }
}
FUZZ_TEST(ProtoPuzzles, PrefixBytesSummingToMagicValue);

void PrefixIsMagicValue(const TestProtobuf& input) {
  if (input.str().size() < 2) {
    return;
  }
  if (input.str()[0] + input.str()[1] == 0x72) {
    std::abort();
  }
}
FUZZ_TEST(ProtoPuzzles, PrefixIsMagicValue);

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

}  // namespace
