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

// Tests of DomainBuilder.

#include <bitset>
#include <cctype>
#include <deque>
#include <iterator>
#include <list>
#include <optional>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/random/random.h"
#include "./fuzztest/domain_core.h"
#include "./domain_tests/domain_testing.h"

namespace fuzztest {
namespace {

struct Tree {
  int value;
  std::vector<Tree> children;
};

Domain<Tree> ArbitraryTree() {
  DomainBuilder builder;
  builder.Set<Tree>(
      "tree", StructOf<Tree>(InRange(0, 10), ContainerOf<std::vector<Tree>>(
                                                 builder.Get<Tree>("tree"))));
  return std::move(builder).Finalize<Tree>("tree");
}

TEST(DomainBuilder, DomainForRecursiveDataStructureCreatesUniqueObjects) {
  // The domain should outlive the builder.
  Domain<Tree> domain = ArbitraryTree();

  absl::BitGen bitgen;
  Value tree(domain, bitgen);

  while (true) {
    tree.Mutate(domain, bitgen, {}, false);
    if (tree.user_value.children.empty()) continue;
    if (tree.user_value.children[0].children.empty()) continue;
    if (tree.user_value.children[0].children[0].children.empty()) continue;
    break;
  }
}

struct RedTree;

struct BlackTree {
  int value;
  std::vector<RedTree> children;
};

struct RedTree {
  int value;
  std::vector<BlackTree> children;
};

Domain<RedTree> ArbitraryRedBlackTree() {
  DomainBuilder builder;
  builder.Set<RedTree>(
      "redtree", StructOf<RedTree>(InRange(0, 10),
                                   ContainerOf<std::vector<BlackTree>>(
                                       builder.Get<BlackTree>("blacktree"))));
  builder.Set<BlackTree>(
      "blacktree", StructOf<BlackTree>(InRange(0, 10),
                                       ContainerOf<std::vector<RedTree>>(
                                           builder.Get<RedTree>("redtree"))));

  return std::move(builder).Finalize<RedTree>("redtree");
}

TEST(DomainBuilder,
     DomainForMutuallyRecursiveDataStructureCreatesUniqueObjects) {
  Domain<RedTree> domain_redtree = ArbitraryRedBlackTree();

  absl::BitGen bitgen;
  Value redtree(domain_redtree, bitgen);
  while (true) {
    redtree.Mutate(domain_redtree, bitgen, {}, false);
    if (redtree.user_value.children.empty()) continue;
    if (redtree.user_value.children[0].children.empty()) continue;
    if (redtree.user_value.children[0].children[0].children.empty()) continue;
    break;
  }
}

TEST(DomainBuilder, DiesOnInvalidFinalize) {
  DomainBuilder builder;
  builder.Set<int>("example", Just(0));

  EXPECT_DEATH_IF_SUPPORTED(
      std::move(builder).Finalize<int>("typo"),
      "Finalize\\(\\) has been called with an unknown name: typo");
}

}  // namespace
}  // namespace fuzztest
