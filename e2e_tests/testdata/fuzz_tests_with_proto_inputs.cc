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
#include "absl/algorithm/container.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/types/span.h"
#include "./fuzztest/fuzztest.h"
#include "./fuzztest/internal/test_protobuf.pb.h"
#include "google/protobuf/text_format.h"
#include "re2/re2.h"

namespace {

using ::fuzztest::internal::CalculatorExpression;
using ::fuzztest::internal::DataColumnFilter;
using ::fuzztest::internal::FoodMachineProcedure;
using ::fuzztest::internal::MazePath;
using ::fuzztest::internal::NodeGraph;
using ::fuzztest::internal::RoboCourier560Plan;
using ::fuzztest::internal::SingleBytesField;
using ::fuzztest::internal::TestProtobuf;
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

  int valid_urls = 0;
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
      && i[0] > 0                 // Postive.
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

void RunMaze(const MazePath& path) {
  constexpr int kMaxPathLength = 32;
  constexpr int kHeight = 7;
  constexpr int kWidth = 11;
  // clang-format off
  constexpr char kMaze[kHeight][kWidth+1] = {
    "+-+---+---+",
    "| |     |#|",
    "| | --+ | |",
    "| |   | | |",
    "| +-- | | |",
    "|     |   |",
    "+-----+---+"};
  // clang-format on

  int x = 1, y = 1;    // Current position.
  int prev_x, prev_y;  // Previous position.

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

    if (kMaze[y][x] != ' ') {
      std::cout << "Cannot go there!\n";
      x = prev_x;
      y = prev_y;
      break;
    }
  }

  // Lose if we didn't reach the target.
  std::cout << "You lost.\n";
}
FUZZ_TEST(ProtoPuzzles, RunMaze);

TEST(ProtoPuzzles, RunMazeReproducer) {
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
  EXPECT_DEATH(RunMaze(path), "SIGABRT");
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

}  // namespace
