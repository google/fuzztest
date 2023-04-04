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

// Example fuzz tests that require GoogleTest, for functional testing.
//
// Used by `functional_test` only. We separate these into a different .cc file
// to show that regular FUZZ_TEST work without having to #include GoogleTest.

#include <cstdio>
#include <limits>

#include "gtest/gtest.h"
#include "./fuzztest/fuzztest.h"
#include "./fuzztest/googletest_fixture_adapter.h"

struct MySuiteSeedsFixture {
  void AddCall(std::string s) {
    if (s == "UnguessableExampleSeed") {
      fprintf(stderr,
              "<<MySuiteSeedsFixture::GuessedUnguessableExampleSeed>>\n");
    }
  }

  std::vector<std::tuple<std::string>> GetDynamicFuzzTestSeeds() {
    return {"UnguessableExampleSeed"};
  }
};
FUZZ_TEST_F(MySuiteSeedsFixture, AddCall);
