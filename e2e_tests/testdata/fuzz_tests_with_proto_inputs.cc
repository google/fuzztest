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

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <limits>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "./fuzztest/fuzztest.h"
#include "absl/algorithm/container.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzztest/internal/test_protobuf.pb.h"
#include "google/protobuf/text_format.h"
#include "re2/re2.h"

namespace {

using ::fuzztest::internal::CalculatorExpression;
using ::fuzztest::internal::DataColumnFilter;
using ::fuzztest::internal::FoodMachineProcedure;
using ::fuzztest::internal::Matrix;
using ::fuzztest::internal::MazeKeys;
using ::fuzztest::internal::MazePath;
using ::fuzztest::internal::NodeGraph;
using ::fuzztest::internal::Person;
using ::fuzztest::internal::RoboCourier560Plan;
using ::fuzztest::internal::SingleBytesField;
using ::fuzztest::internal::TcpStateMachine;
using ::fuzztest::internal::TestProtobuf;
using ::fuzztest::internal::Vector;
using ::fuzztest::internal::WebSearchResult;

void Target() {
  std::cout << "[¡Target Reached!]" << std::endl;
#ifndef FUZZTEST_INTERNAL_DO_NOT_CRASH_ON_TARGET
  std::abort();
#endif
}

void BytesSummingToMagicValue(const SingleBytesField& input) {
  char sum = 0;
  for (const char c : input.data()) {
    sum += c;
  }
  if (sum == 0x72) {
    Target();
  }
}
FUZZ_TEST(ProtoPuzzles, BytesSummingToMagicValue);

void BytesSummingToMagicValueWithOverloadedProto(const TestProtobuf& input) {
  char sum = 0;
  for (const char c : input.str()) {
    sum += c;
  }
  if (sum == 0x72) {
    Target();
  }
}
FUZZ_TEST(ProtoPuzzles, BytesSummingToMagicValueWithOverloadedProto);

void PrefixBytesSummingToMagicValue(const SingleBytesField& input) {
  if (input.data().size() < 2) {
    return;
  }
  if (input.data()[0] + input.data()[1] == 0x72) {
    Target();
  }
}
FUZZ_TEST(ProtoPuzzles, PrefixBytesSummingToMagicValue);

void PrefixBytesSummingToMagicValueWithOverloadedProto(
    const TestProtobuf& input) {
  if (input.str().size() < 2) {
    return;
  }
  if (input.str()[0] + input.str()[1] == 0x72) {
    Target();
  }
}
FUZZ_TEST(ProtoPuzzles, PrefixBytesSummingToMagicValueWithOverloadedProto);

void PrefixIsMagicValue(const SingleBytesField& input) {
  if (input.data().size() < 2) {
    return;
  }
  if (input.data()[0] + input.data()[1] == 0x72) {
    Target();
  }
}
FUZZ_TEST(ProtoPuzzles, PrefixIsMagicValue);

void PrefixIsMagicValueWithOverloadedProto(const TestProtobuf& input) {
  if (input.str().size() < 2) {
    return;
  }
  if (input.str()[0] + input.str()[1] == 0x72) {
    Target();
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
    Target();
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
    Target();
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
        if (machine_contents.empty()) {
          Target();
        }
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
              DeliveryResult{/*location_name=*/name,
                             /*location_address=*/mail.address(),
                             /*mail_name=*/mail.name(),
                             /*mail_content=*/extra_action.content()});
          break;
        }
      }
    }
    results.push_back(DeliveryResult{/*location_name=*/name,
                                     /*location_address=*/mail.address(),
                                     /*mail_name=*/mail.name(),
                                     /*mail_content=*/mail.content()});
  }
  return results;
}

void RunRoboCourier560(const RoboCourier560Plan& plan) {
  const std::vector<DeliveryResult> results = RoboCourierRun(plan);

  for (const DeliveryResult& result : results) {
    if (result.location_name != result.mail_name) {
      // [Hint] Mail delivered to the wrong name. Can happen if mail is
      // delivered at before a `CHANGE_NAME` action.
      Target();
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
  Target();
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
  Target();
}
FUZZ_TEST(ProtoPuzzles, IntegerConditionsOnTestProtobufLevel01);

void IntegerConditionsOnTestProtobufLevel02(const TestProtobuf& input) {
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

  uint64_t rep_u32_result = 0;
  if (input.rep_u32().size() < 10) {
    return;
  }
  for (int i = 0; i < input.rep_u32().size(); ++i) {
    if (input.rep_b()[i % input.rep_b().size()]) {
      rep_u32_result += input.rep_u32()[i];
    } else {
      rep_u32_result -= input.rep_u32()[i];
    }
  }
  if (rep_u32_result < 65377) {
    return;
  }
  // [Hint] Can happen if none of the early returns above are taken.
  Target();
}
FUZZ_TEST(ProtoPuzzles, IntegerConditionsOnTestProtobufLevel02);

static bool IsValidUrl(const std::string& url) {
  const std::string url_pattern =
      R"(^(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]$)";
  return RE2::FullMatch(url, url_pattern);
}

void ValidateUrls(const WebSearchResult& search_result) {
  // Search result must contain at least 1 URL.
  if (search_result.count() <= 0) {
    return;
  }

  // Search result must contain at most 10 URLs.
  if (search_result.count() > 10) {
    return;
  }

  // Query should be at least 2 letters in size.
  if (search_result.query().empty() || search_result.query().size() < 2) {
    return;
  }

  // Search result must contain exactly `count` URLs.
  if (search_result.urls_size() != search_result.count()) {
    return;
  }

  [[maybe_unused]] int valid_urls = 0;
  std::unordered_set<std::string> unique_urls;

  for (const auto& url : search_result.urls()) {
    // Check if url is a valid url.
    if (IsValidUrl(url)) {
      valid_urls++;
      unique_urls.insert(url);
    }
  }

  // Ensure that all valid URLs are unique.
  if (unique_urls.size() != search_result.urls_size()) {
    return;
  }
  Target();
}
FUZZ_TEST(ProtoPuzzles, ValidateUrls);

void QueryOfDeath(const WebSearchResult& input) {
  if (input.query() == "QoD") {
    Target();
  }
}

FUZZ_TEST(ProtoPuzzles, QueryOfDeath);

void StringsReverseEqual(const TestProtobuf& input) {
  if (input.rep_str().size() < 2) {
    return;
  }
  const std::string left = input.rep_str()[0];
  const std::string right = input.rep_str()[1];
  if (left.size() < 2) {
    return;
  }
  if (right.size() < 2) {
    return;
  }
  if (left == right) {
    return;
  }
  if (std::equal(left.begin(), left.end(), right.rbegin(), right.rend())) {
    // [Hint] Reachable if the strings are "reverse equal" to each other.
    Target();
  }
}
FUZZ_TEST(ProtoPuzzles, StringsReverseEqual);

void StdCharacterFunctions(const SingleBytesField& input) {
  if (input.data().size() < 16) return;
  if (std::isalnum(input.data()[0]) && std::isalpha(input.data()[1]) &&
      std::isdigit(input.data()[2]) && std::isblank(input.data()[3]) &&
      std::iscntrl(input.data()[4]) && std::isdigit(input.data()[5]) &&
      std::isgraph(input.data()[6]) && std::islower(input.data()[7]) &&
      std::isprint(input.data()[8]) && std::ispunct(input.data()[9]) &&
      std::isspace(input.data()[10]) && std::isupper(input.data()[11]) &&
      std::isxdigit(input.data()[12]) &&
      'Q' == std::toupper(input.data()[13]) &&
      'o' == std::tolower(input.data()[14]) &&
      'D' == std::toupper(input.data()[15])) {
    Target();
  }
}
FUZZ_TEST(ProtoPuzzles, StdCharacterFunctions);

void MathFunctions(const TestProtobuf& input) {
  // Doubles.
  if (input.rep_d_size() < 92) return;
  const auto& d = input.rep_d();

  // Integers.
  if (input.rep_i64_size() < 6) return;
  const auto& i = input.rep_i64();

  // Temporary output values.
  double d_tmp;
  int i_tmp;

  if (
      // Basic operations.
      d[0] < 0                    // Negative.
      && i[0] > 0                 // Positive.
      && std::fabs(d[0]) == i[0]  // |x|.

      // Remainder and qoutient functions.
      && d[1] == std::fmod(d[2], 4.9)        // Remainder of division.
      && d[3] == std::remainder(d[4], 3.12)  // Signed remainder.
      && d[5] == std::remquo(d[6], 1.1,
                             &i_tmp)  // Signed remainder and 3 last bits.

      // Exponential functions.
      && d[7] == std::exp(d[8])      // e^x.
      && d[9] == std::exp2(d[10])    // 2^x.
      && d[11] == std::expm1(d[12])  // e^x - 1.

      // Logarithmic functions.
      && d[13] == std::log(d[14])    // ln x.
      && d[15] == std::log10(d[16])  // log_10(x).
      && d[17] == std::log2(d[18])   // log_2(x).
      && d[19] == std::log1p(d[20])  // ln(x + 1).

      // Power functions.
      && d[21] == std::pow(6, d[22])        // 6^x.
      && d[23] == std::sqrt(d[24])          // Square root.
      && d[25] == std::cbrt(d[26])          // Cubic root.
      && d[27] == std::hypot(d[28], d[29])  // Euclidean distance.

      // Trigonometric functions.
      && d[30] == std::sin(d[31])           // Sine.
      && d[32] == std::cos(d[33])           // Cosine.
      && d[33] == std::tan(d[35])           // Tangent.
      && d[36] == std::asin(d[37] - 1)      // Arc sine.
      && d[38] == std::acos(d[39] - 1)      // Arc cosine.
      && d[40] == std::atan(d[41])          // Arc tangent.
      && d[42] == std::atan2(d[43], d[44])  // Use signs to determine quadrants.

      // Hyperbolic functions.
      && d[45] == std::sinh(d[46])       // Hyperbolic sine.
      && d[47] == std::cosh(d[48])       // Hyperbolic cosine.
      && d[49] == std::tanh(d[50])       // Hyperbolic tangent.
      && d[51] == std::asinh(d[52] - 1)  // Inverse hyperbolic sine.
      && d[53] == std::acosh(d[54] - 1)  // Inverse hyperbolic cosine.
      && d[55] == std::atanh(d[56])      // Inverse hyperbolic tangent.

      // Nearest integer floating point operations.
      && d[57] == std::ceil(d[58])    // Nearest int, not less than.
      && d[59] == std::floor(d[60])   // Nearest int, not greater than.
      && d[61] == std::trunc(d[62])   // Nearest int, not greater in magnitude.
      && d[63] == std::round(d[64])   // Round away from 0 in halfway cases.
      && i[1] == std::lround(d[65])   // Round to long.
      && i[2] == std::llround(d[66])  // Round to long long.
      && d[67] == std::nearbyint(d[68])  // Using current rounding mode.
      && d[69] == std::rint(d[70])       // Using current rounding mode,
                                         // except if the result differs.
      && i[3] == std::lrint(d[71])       // Round to long.
      && i[4] == std::llrint(d[72])      // Round to long long.

      // Floating point manipulation functions.
      && d[73] == std::frexp(d[74], &i_tmp)  // Significand and pow of 2.
      && d[75] == std::ldexp(d[76], 3)       // Multiplies by 2^x.
      && d[77] == std::modf(d[78], &d_tmp)   // Return fractional part.
      && d[79] == std::scalbn(d[80], 3)      // Multiply by radix^x.
      && d[81] == std::scalbln(d[82], 3)     // Long exponent.
      && i[5] == std::ilogb(d[83])           // Extracts exponent of the number.
      && d[84] == std::logb(d[85])           // Extracts exponent of the number.

      // Classification and comparison.
      && std::fpclassify(d[86]) == FP_SUBNORMAL  // Too small to be represented.
      && !std::isfinite(d[87])                   // Not a finate value.
      && std::isinf(d[89])                       // Is infinate.
      && std::isnan(d[90])                       // Is "not a number".
      && !std::isnormal(d[91])  // Not a normal floating number.
  ) {
    Target();
  }
}
FUZZ_TEST(ProtoPuzzles, MathFunctions);

void RunMaze(const MazePath& path, const MazeKeys& keys) {
  constexpr int kMaxPathLength = 32;
  constexpr int kHeight = 7;
  constexpr int kWidth = 11;
  // clang-format off
  // Numbers represent doors that need to be unlocked by the corresponding keys.
  constexpr char kMaze[kHeight][kWidth+1] = {
    "+-+---+---+",
    "| | 4   |#|",
    "|2| --+ |5|",
    "| |   |3| |",
    "|7+--6| |9|",
    "|   1 | 8 |",
    "+-----+---+"};
  // clang-format on

  int x = 1, y = 1;    // Current position.
  int prev_x, prev_y;  // Previous position.
  int key_idx = 0;     // The next unused key.

  for (int i = 0; i < path.direction_size() && i < kMaxPathLength; ++i) {
    prev_x = x;
    prev_y = y;

    switch (path.direction(i)) {
      case MazePath::UP:
        y--;
        break;
      case MazePath::DOWN:
        y++;
        break;
      case MazePath::LEFT:
        x--;
        break;
      case MazePath::RIGHT:
        x++;
        break;
      case MazePath::UNSPECIFIED:
      default:
        std::cout << "Invalid input!\n";
        return;
    }

    if (kMaze[y][x] == '#') {
      std::cout << "You won!\n";
      Target();
      return;
    }

    if (std::isdigit(kMaze[y][x])) {
      const bool is_locked =
          key_idx >= keys.key_size() || keys.key(key_idx) != kMaze[y][x] - '0';
      if (is_locked) {
        std::cout << "The door is locked!\n";
        x = prev_x;
        y = prev_y;
        break;
      }
      ++key_idx;
    } else if (kMaze[y][x] != ' ') {
      std::cout << "Cannot go there!\n";
      x = prev_x;
      y = prev_y;
      break;
    }
  }

  // Lose if we didn't reach the target.
  std::cout << "You lost.\n";
}

MazePath GetCorrectMazePath() {
  MazePath path;
  path.add_direction(MazePath::DOWN);
  path.add_direction(MazePath::DOWN);
  path.add_direction(MazePath::DOWN);
  path.add_direction(MazePath::DOWN);
  path.add_direction(MazePath::RIGHT);
  path.add_direction(MazePath::RIGHT);
  path.add_direction(MazePath::RIGHT);
  path.add_direction(MazePath::RIGHT);
  path.add_direction(MazePath::UP);
  path.add_direction(MazePath::UP);
  path.add_direction(MazePath::LEFT);
  path.add_direction(MazePath::LEFT);
  path.add_direction(MazePath::UP);
  path.add_direction(MazePath::UP);
  path.add_direction(MazePath::RIGHT);
  path.add_direction(MazePath::RIGHT);
  path.add_direction(MazePath::RIGHT);
  path.add_direction(MazePath::RIGHT);
  path.add_direction(MazePath::DOWN);
  path.add_direction(MazePath::DOWN);
  path.add_direction(MazePath::DOWN);
  path.add_direction(MazePath::DOWN);
  path.add_direction(MazePath::RIGHT);
  path.add_direction(MazePath::RIGHT);
  path.add_direction(MazePath::UP);
  path.add_direction(MazePath::UP);
  path.add_direction(MazePath::UP);
  path.add_direction(MazePath::UP);
  return path;
}

MazeKeys GetCorrectMazeKeys() {
  MazeKeys keys;
  keys.add_key(2);
  keys.add_key(7);
  keys.add_key(1);
  keys.add_key(6);
  keys.add_key(4);
  keys.add_key(3);
  keys.add_key(8);
  keys.add_key(9);
  keys.add_key(5);
  return keys;
}

void RunMazeWithPath(const MazePath& path) {
  RunMaze(path, GetCorrectMazeKeys());
}
FUZZ_TEST(ProtoPuzzles, RunMazeWithPath);

void RunMazeWithKeys(const MazeKeys& keys) {
  RunMaze(GetCorrectMazePath(), keys);
}
FUZZ_TEST(ProtoPuzzles, RunMazeWithKeys);

TEST(ProtoPuzzles, RunMazeReproducer) {
  EXPECT_DEATH(RunMaze(GetCorrectMazePath(), GetCorrectMazeKeys()), "SIGABRT");
}

// Check that all nodes in the graphs are reachable from the start node.
void GraphReachability(const NodeGraph& graph) {
  if (graph.node_size() < 5) {
    // We constrain the inputs to reasonably-sized graphs.
    return;
  }

  // Build a node index first, so they can be looked up efficiently using their
  // names.
  absl::flat_hash_map<std::string, const NodeGraph::Node*> node_map;
  for (const NodeGraph::Node& node : graph.node()) {
    if (node.name().empty() || !node_map.insert({node.name(), &node}).second) {
      // Malformed graph: invalid node names.
      return;
    }
  }

  // Traverse the graph in a BFS manner starting from the start node.
  absl::flat_hash_set<std::string> reached_nodes;
  std::deque<std::string> node_frontier{graph.start()};
  while (!node_frontier.empty()) {
    const std::string node_name = std::move(node_frontier.front());
    node_frontier.pop_front();

    // Whereas the reached nodes are resolved, the frontier of nodes are just
    // strings that need to be validated first.
    if (auto it = node_map.find(node_name); it != node_map.end()) {
      if (reached_nodes.insert(it->second->name()).second) {
        for (const auto& successor : it->second->successor()) {
          node_frontier.push_back(successor);
        }
      }
    } else {
      // Malformed graph: invalid start or successor names.
      return;
    }
  }
  if (reached_nodes.size() == graph.node_size()) {
    Target();
  }
}
FUZZ_TEST(ProtoPuzzles, GraphReachability);

TEST(ProtoPuzzles, GraphReachabilityReproducer) {
  NodeGraph graph;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"textpb(
        node {
          name: "a"
          successor: "b"
          successor: "c"
        }
        node {
          name: "b"
          successor: "d"
        }
        node {
          name: "c"
          successor: "a"
          successor: "b"
          successor: "e"
        }
        node {
          name: "d"
          successor: "b"
        }
        node {
          name: "e"
          successor: "e"
        }
        start: "a"
      )textpb",
      &graph));
  EXPECT_DEATH(GraphReachability(graph), "SIGABRT");
}

void RemainderEquations(const TestProtobuf& input) {
  if (input.u32() % 56807 != 1) return;
  if (input.u32() % 56809 != 2) return;
  Target();
}
FUZZ_TEST(ProtoPuzzles, RemainderEquations);

TEST(ProtoPuzzles, RemainderEquationsReproducer) {
  TestProtobuf input;
  input.set_u32(1613546029);
  EXPECT_DEATH(RemainderEquations(input), "SIGABRT");
}

void ValidateFiltersNotEmptyHelper(
    const DataColumnFilter& data_column_filter,
    std::vector<DataColumnFilter::FilterCase>& case_stack) {
  if (absl::c_equal(case_stack,
                    absl::MakeConstSpan({DataColumnFilter::kAndFilter,
                                         DataColumnFilter::kOrFilter,
                                         DataColumnFilter::kNotFilter}))) {
    Target();
  }
  switch (data_column_filter.filter_case()) {
    case DataColumnFilter::kAndFilter: {
      case_stack.push_back(DataColumnFilter::kAndFilter);
      if (data_column_filter.and_filter().filters_size() >= 2) {
        for (const DataColumnFilter& sub_filter :
             data_column_filter.and_filter().filters()) {
          ValidateFiltersNotEmptyHelper(sub_filter, case_stack);
        }
      }
      break;
    }
    case DataColumnFilter::kOrFilter: {
      case_stack.push_back(DataColumnFilter::kOrFilter);
      if (data_column_filter.or_filter().filters_size() >= 2) {
        for (const DataColumnFilter& sub_filter :
             data_column_filter.or_filter().filters()) {
          ValidateFiltersNotEmptyHelper(sub_filter, case_stack);
        }
      }
      break;
    }
    case DataColumnFilter::kNotFilter: {
      case_stack.push_back(DataColumnFilter::kNotFilter);
      if (data_column_filter.not_filter().has_filter()) {
        ValidateFiltersNotEmptyHelper(data_column_filter.not_filter().filter(),
                                      case_stack);
      }
      break;
    }
    case DataColumnFilter::FILTER_NOT_SET:
      break;
  }
}

void ValidateFiltersNotEmpty(const DataColumnFilter& data_column_filter) {
  std::vector<DataColumnFilter::FilterCase> case_stack;
  ValidateFiltersNotEmptyHelper(data_column_filter, case_stack);
}
FUZZ_TEST(ProtoPuzzles, ValidateFiltersNotEmpty);

TEST(ProtoPuzzles, ValidateFiltersNotEmptyReproducer) {
  DataColumnFilter data_column_filter;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"textpb(
        and_filter {
          filters {
            or_filter {
              filters { not_filter {} }
              filters { not_filter {} }
            }
          }
          filters { not_filter {} }
        }
      )textpb",
      &data_column_filter));
  EXPECT_DEATH(ValidateFiltersNotEmpty(data_column_filter), "SIGABRT");
}

void SingleCycle(const TestProtobuf& input) {
  if (input.rep_u32_size() < 10) return;
  // Floyd's cycle-finding algorithm.
  size_t cycle_size = 0;  // 0 means cycle is not found.
  size_t slow_cursor = 0;
  size_t fast_cursor = 0;
  while (true) {
    // The fast cursor moves two steps at a time.
    fast_cursor = input.rep_u32()[fast_cursor];
    if (fast_cursor >= input.rep_u32_size()) break;
    fast_cursor = input.rep_u32()[fast_cursor];
    if (fast_cursor >= input.rep_u32_size()) break;
    // The slow cursor moves one step at a time. No need for bound checking.
    slow_cursor = input.rep_u32()[slow_cursor];
    if (fast_cursor == slow_cursor) {
      // This will eventually happen as long as the cursors stay in the range.
      if (cycle_size > 0) break;
      cycle_size = 1;
    } else {
      if (cycle_size > 0) ++cycle_size;
    }
  }
  if (cycle_size != input.rep_u32_size()) return;
  Target();
}
FUZZ_TEST(ProtoPuzzles, SingleCycle);

TEST(ProtoPuzzles, SingleCycleReproducer) {
  TestProtobuf input;
  input.add_rep_u32(1);
  input.add_rep_u32(2);
  input.add_rep_u32(3);
  input.add_rep_u32(4);
  input.add_rep_u32(5);
  input.add_rep_u32(6);
  input.add_rep_u32(7);
  input.add_rep_u32(8);
  input.add_rep_u32(9);
  input.add_rep_u32(0);
  EXPECT_DEATH(SingleCycle(input), "SIGABRT");
}

static std::vector<uint32_t> AdjacentDifference(
    absl::Span<const uint32_t> seq) {
  if (seq.size() <= 1) return {};
  std::vector<uint32_t> result;
  result.reserve(seq.size() - 1);
  for (size_t i = 1; i < seq.size(); ++i) {
    result.push_back(seq[i] - seq[i - 1]);
  }
  return result;
}

void IncreasingQuadraticSequence(const TestProtobuf& input) {
  if (input.rep_u32().size() < 10) return;
  for (size_t i = 0; i < input.rep_u32().size() - 1; ++i) {
    if (input.rep_u32()[i] >= input.rep_u32()[i + 1]) return;
  }
  const auto diff2 = AdjacentDifference(AdjacentDifference(input.rep_u32()));
  if (diff2[0] == 0) return;
  for (size_t i = 1; i < diff2.size(); ++i) {
    if (diff2[i] != diff2[0]) return;
  }
  Target();
}
FUZZ_TEST(ProtoPuzzles, IncreasingQuadraticSequence);

TEST(ProtoPuzzles, IncreasingQuadraticSequenceReproducer) {
  TestProtobuf input;
  input.add_rep_u32(1);
  input.add_rep_u32(4);
  input.add_rep_u32(9);
  input.add_rep_u32(16);
  input.add_rep_u32(25);
  input.add_rep_u32(36);
  input.add_rep_u32(49);
  input.add_rep_u32(64);
  input.add_rep_u32(81);
  input.add_rep_u32(100);
  EXPECT_DEATH(IncreasingQuadraticSequence(input), "SIGABRT");
}

bool NeedsValidSupervisor(const Person& person) {
  return person.age() < 18 || person.age() > 80;
}

bool CanSupervise(const Person& person1, const Person& person2) {
  if (!NeedsValidSupervisor(person2)) return false;
  // For an old person, the supervisor should be younger.
  if (person2.age() > 80 && person1.age() < person2.age() &&
      person1.age() >= 18) {
    return true;
  }
  // For a young person, the supervisor should be older.
  if (person2.age() < 18 && person1.age() > person2.age() &&
      person1.age() <= 80) {
    return true;
  }
  return false;
}

// Determine whether `input` has at least two direct or indirect legal
// supervisor (18 <= supervisor.age <= 80), one of which is local.
void HasLegalSupervisors(const Person& input) {
  if (!NeedsValidSupervisor(input)) return;
  std::vector<Person> persons;
  std::vector<Person> legal_supervisors;
  persons.push_back(input);
  while (!persons.empty()) {
    Person person = persons.back();
    persons.pop_back();
    if (!NeedsValidSupervisor(person)) {
      legal_supervisors.push_back(person);
      continue;
    }
    for (const auto& emergency_contact : person.emergency_contacts()) {
      if (CanSupervise(emergency_contact, person)) {
        persons.push_back(emergency_contact);
      }
    }
  }
  if (legal_supervisors.size() < 2) return;
  for (const auto& supervisor : legal_supervisors) {
    if (supervisor.zipcode() == 10014) {  // Need a local supervisor
      Target();
    }
  }
}
FUZZ_TEST(ProtoPuzzles, HasLegalSupervisors);

bool IsPrime(int64_t n) {
  if (n < 2) return false;
  if (n == 2 || n == 3) return true;
  if (n % 2 == 0 || n % 3 == 0) return false;

  constexpr int64_t kDivisorOverflowBound = 3'037'000'499LL;
  // Checks divisors of the form 6k-1 and 6k+1, as these include all the primes.
  for (int64_t d = 5; d <= kDivisorOverflowBound && d * d <= n; d += 6) {
    if (n % d == 0) return false;
    if (n % (d + 2) == 0) return false;
  }
  return true;
}

bool IsPalindrome(int64_t n) {
  if (n < 0) return false;
  std::vector<int64_t> digits;
  while (n > 0) {
    digits.push_back(n % 10);
    n /= 10;
  }
  for (int i = 0; i < digits.size() / 2; ++i) {
    if (digits[i] != digits[digits.size() - i - 1]) return false;
  }
  return true;
}

void CheckingPalindromicPrimesIsFast(const TestProtobuf& input) {
  absl::Time start = absl::Now();
  bool is_palindromic_prime = IsPalindrome(input.i64()) && IsPrime(input.i64());
  absl::Duration elapsed = absl::Now() - start;
  if (elapsed > absl::Seconds(1)) {
    std::cout << "It took " << absl::FormatDuration(elapsed)
              << " to check whether " << input.i64()
              << " is a palindromic prime! (It is"
              << (is_palindromic_prime ? "" : " not") << ".)\n";
    Target();
  }
}
FUZZ_TEST(ProtoPuzzles, CheckingPalindromicPrimesIsFast);

TEST(ProtoPuzzles, CheckingPalindromicPrimesIsFastReproducer) {
  TestProtobuf input;
  input.set_i64(3'791'454'766'674'541'973LL);
  EXPECT_DEATH(CheckingPalindromicPrimesIsFast(input), "SIGABRT");
}

// Check whether the matrix (> 3x3) is symmetric and does not have 0 elements.
void IsValidSymmetricMatrix(const Matrix& matrix) {
  const int size = matrix.columns_size();
  if (size <= 3) return;  // Not interested in small matrices.
  for (int i = 0; i < size; ++i) {
    if (matrix.columns(i).rows_size() != size) return;  // Not a square matrix.
  }
  for (int i = 0; i < size; ++i) {
    if (matrix.columns(i).rows(i) == 0) {
      // Not valid when has elements 0.
      return;
    }
    for (int j = i + 1; j < size; ++j) {
      if (matrix.columns(i).rows(j) == 0) {
        // Not valid when has elements 0.
        return;
      }
      if (matrix.columns(i).rows(j) != matrix.columns(j).rows(i)) {
        // Not a symmetric matrix.
        return;
      }
    }
  }
  std::cout << absl::StrCat("Matrix: ", matrix, "\n");
  Target();
}
FUZZ_TEST(ProtoPuzzles, IsValidSymmetricMatrix);

void DetectShift(const TestProtobuf& input) {
  constexpr size_t kExpectedLoopLength = 10;
  const size_t rep_size = input.rep_u32_size();
  if (rep_size < kExpectedLoopLength) return;
  if (input.rep_u64_size() != rep_size) return;

  for (size_t shift = 0; shift < rep_size; ++shift) {
    bool succeeds = true;
    for (size_t index = 0; index < rep_size; ++index) {
      succeeds &=
          (input.rep_u32(index) == input.rep_u64((index + shift) % rep_size));
    }
    if (succeeds) Target();
  }
}
FUZZ_TEST(ProtoPuzzels, DetectShift);

TEST(ProtoPuzzels, DetectShiftReproducer) {
  TestProtobuf input;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"textpb(
        rep_u32: 1
        rep_u32: 2
        rep_u32: 3
        rep_u32: 4
        rep_u32: 5
        rep_u32: 6
        rep_u32: 7
        rep_u32: 8
        rep_u32: 9
        rep_u32: 0
        rep_u64: 2
        rep_u64: 3
        rep_u64: 4
        rep_u64: 5
        rep_u64: 6
        rep_u64: 7
        rep_u64: 8
        rep_u64: 9
        rep_u64: 0
        rep_u64: 1
      )textpb",
      &input));
  EXPECT_DEATH(DetectShift(input), "SIGABRT");
}

void LongestCommonPrefix(const TestProtobuf& input) {
  if (input.rep_str_size() < 10) return;

  std::string prefix = input.rep_str(0);
  for (const std::string& str : input.rep_str()) {
    prefix = prefix.substr(0, std::min(prefix.size(), str.size()));
    for (size_t idx = 0; idx < str.size() && idx < prefix.size(); ++idx) {
      if (str[idx] != prefix[idx]) {
        prefix = prefix.substr(0, idx);
        break;
      }
    }
  }

  if (!prefix.empty()) {
    Target();
  }
}

FUZZ_TEST(ProtoPuzzles, LongestCommonPrefix);

TEST(ProtoPuzzels, LongestCommonPrefixReproducer) {
  TestProtobuf input;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      R"textpb(
        rep_str: "12321"
        rep_str: "1234321"
        rep_str: "123454321"
        rep_str: "12345654321"
        rep_str: "1234567654321"
        rep_str: "123456787654321"
        rep_str: "12345678987654321"
        rep_str: "1235321"
        rep_str: "12354321"
        rep_str: "123321"
      )textpb",
      &input));
  EXPECT_DEATH(LongestCommonPrefix(input), "SIGABRT");
}

int LargestPowerOfTwoLessThan(int n) {
  CHECK_GT(n, 0);
  while ((n & (n - 1))) {
    n -= n & -n;
  }
  return n;
}

// Nim is an iterative game played by two players on a stack of marbles. Given
// `n > 1` marbles, each player at their turn can remove `[1, n/2]` marbles from
// the stack. The player that remains with only one marble loses.
//
// Player strategy is a map where the player removes `strategy.row(i)` marbles
// when there are `i` marbles left.
void PlayNim(const Vector& strategy) {
  // Initial number of marbles, used to adjust the difficulty.
  int n = 150;
  if (n >= strategy.rows_size()) return;  // Invalid strategy.
  while (true) {
    // Player turn
    if (n <= 1) return;  // Player lost
    int to_remove = strategy.rows(n);
    if (to_remove < 1 || to_remove > n / 2) return;  // Invalid strategy.
    n -= to_remove;

    // Opponent turn
    if (n <= 1) {
      std::cout << absl::StrCat("Strategy: ", strategy, "\n");
      Target();  // Player won.
    }
    if (!(n & (n + 1))) {  // n = 2^p -1
      // No winning strategy. Picking an arbitrary value.
      to_remove = 1;
    } else {
      // Keep 2^p -1 marbles
      to_remove = n - (LargestPowerOfTwoLessThan(n) - 1);
    }
    CHECK(to_remove >= 1 && to_remove <= n / 2);  // Invalid move.
    n -= to_remove;
  }
}
FUZZ_TEST(ProtoPuzzles, PlayNim);

TcpStateMachine::State ClosedStateEventHandler(TcpStateMachine::Event event) {
  switch (event) {
    case TcpStateMachine::USER_LISTEN:
      return TcpStateMachine::LISTEN;
    case TcpStateMachine::USER_CONNECT:
      return TcpStateMachine::SYN_SENT;
    default:
      return TcpStateMachine::CLOSED;
  }
}

TcpStateMachine::State ListenStateEventHandler(TcpStateMachine::Event event) {
  switch (event) {
    case TcpStateMachine::RCV_SYN:
      return TcpStateMachine::SYN_RCVD;
    default:
      return TcpStateMachine::LISTEN;
  }
}

TcpStateMachine::State SynRcvdStateEventHandler(TcpStateMachine::Event event) {
  switch (event) {
    case TcpStateMachine::RCV_ACK:
      return TcpStateMachine::ESTABLISHED;
    default:
      return TcpStateMachine::SYN_RCVD;
  }
}

TcpStateMachine::State SynSentStateEventHandler(TcpStateMachine::Event event) {
  switch (event) {
    case TcpStateMachine::RCV_SYN_ACK:
      return TcpStateMachine::ESTABLISHED;
    default:
      return TcpStateMachine::SYN_SENT;
  }
}

TcpStateMachine::State EstablishedStateEventHandler(
    TcpStateMachine::Event event) {
  return TcpStateMachine::ESTABLISHED;
}

void TcpProcessEvents(const TcpStateMachine& state_machine) {
  auto state = state_machine.start_state();

  if (state == TcpStateMachine::ESTABLISHED ||
      state == TcpStateMachine::INVALID_STATE) {
    return;
  }

  for (int i = 0; i < state_machine.event_size(); ++i) {
    auto event = state_machine.event(i);
    switch (state) {
      case TcpStateMachine::CLOSED:
        state = ClosedStateEventHandler(event);
        break;
      case TcpStateMachine::LISTEN:
        state = ListenStateEventHandler(event);
        break;
      case TcpStateMachine::SYN_RCVD:
        state = SynRcvdStateEventHandler(event);
        break;
      case TcpStateMachine::SYN_SENT:
        state = SynSentStateEventHandler(event);
        break;
      case TcpStateMachine::ESTABLISHED:
        state = EstablishedStateEventHandler(event);
        break;
      case TcpStateMachine::INVALID_STATE:
        break;
    }
    if (state == TcpStateMachine::ESTABLISHED) {
      Target();
    }
  }
}

FUZZ_TEST(ProtoPuzzles, TcpProcessEvents);

TEST(ProtoPuzzles, TcpProcessEventsReproducer) {
  TcpStateMachine state_machine;

  state_machine.set_start_state(TcpStateMachine::CLOSED);
  state_machine.add_event(TcpStateMachine::USER_LISTEN);
  state_machine.add_event(TcpStateMachine::RCV_SYN);
  state_machine.add_event(TcpStateMachine::RCV_ACK);
  EXPECT_DEATH(TcpProcessEvents(state_machine), "SIGABRT");
}

void IsValidMinesweeperBoard(const Matrix& board) {
  // Check if the board is at least 3x3 in size.
  const int rows = board.columns_size();
  if (rows <= 3) return;
  const int cols = board.columns(0).rows_size();
  if (cols <= 3) return;

  for (int i = 0; i < rows; ++i) {
    if (board.columns(i).rows_size() != cols) {
      // Rows are not the same size.
      return;
    }
  }

  // Check if the number of bombs is within range of the expected number of
  // bombs.
  const int min_bomb_count = rows * cols * 0.15;
  const int max_bomb_count = rows * cols * 0.25;
  int num_bombs = 0;
  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < cols; j++) {
      if (board.columns(i).rows(j) == -1) {
        num_bombs++;
      }
    }
  }
  if (num_bombs < min_bomb_count || num_bombs > max_bomb_count) {
    // Either too little or too many bombs.
    return;
  }

  // Check if the board is valid.
  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < cols; j++) {
      if (board.columns(i).rows(j) == -1) {
        continue;
      }

      // Count the number of bombs around a cell.
      int count = 0;
      for (int x = i - 1; x <= i + 1; x++) {
        for (int y = j - 1; y <= j + 1; y++) {
          // Make sure we stay within the bounds of the board and check for the
          // presence of surrounding bombs.
          if (x >= 0 && x < rows && y >= 0 && y < cols &&
              board.columns(x).rows(y) == -1) {
            count++;
          }
        }
      }

      if (board.columns(i).rows(j) != count) {
        // Incorrect number of bombs surrounding cell.
        return;
      }
    }
  }
  Target();
}
FUZZ_TEST(ProtoPuzzles, IsValidMinesweeperBoard);
}  // namespace
