// Copyright 2025 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./centipede/centipede_callbacks.h"

#include <string_view>
#include <vector>

#include "gtest/gtest.h"
#include "./centipede/environment.h"
#include "./centipede/runner_result.h"
#include "./common/defs.h"

namespace fuzztest::internal {
namespace {

class FakeCallbacks : public CentipedeCallbacks {
 public:
  explicit FakeCallbacks(const Environment& env) : CentipedeCallbacks(env) {}
  bool Execute(std::string_view binary, const std::vector<ByteSpan>& inputs,
               BatchResult& batch_result) override {
    return true;
  }
};

TEST(NonOwningCallbacksFactoryTest, CreateReturnsUnderlyingCallbacks) {
  Environment env;
  FakeCallbacks callbacks(env);
  NonOwningCallbacksFactory factory(callbacks);
  EXPECT_EQ(factory.create(env), &callbacks);
}

TEST(NonOwningCallbacksFactoryTest, CannotCreateTwice) {
  Environment env;
  FakeCallbacks callbacks(env);
  NonOwningCallbacksFactory factory(callbacks);
  factory.create(env);
  EXPECT_DEATH(factory.create(env), "create\\(\\) called before destroy\\(\\)");
}

TEST(NonOwningCallbacksFactoryTest, CannotDestroyBeforeCreate) {
  Environment env;
  FakeCallbacks callbacks(env);
  NonOwningCallbacksFactory factory(callbacks);
  EXPECT_DEATH(factory.destroy(&callbacks),
               "destroy\\(\\) called before the matching create\\(\\)");
}

TEST(NonOwningCallbacksFactoryTest, CannotDestroyTwice) {
  Environment env;
  FakeCallbacks callbacks(env);
  NonOwningCallbacksFactory factory(callbacks);
  factory.create(env);
  factory.destroy(&callbacks);
  EXPECT_DEATH(factory.destroy(&callbacks),
               "destroy\\(\\) called before the matching create\\(\\)");
}

}  // namespace
}  // namespace fuzztest::internal
