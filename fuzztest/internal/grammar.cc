#include "./fuzztest/internal/grammar.h"

#include <cstddef>
#include <type_traits>
#include <variant>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "./fuzztest/internal/domain.h"
#include "./fuzztest/internal/serialization.h"

namespace fuzztest::internal::grammar {

void GroupElementByASTType(
    ASTNode& astnode,
    absl::flat_hash_map<ASTTypeId, std::vector<ASTNode*>>& groups) {
  groups[astnode.type_id].push_back(&astnode);
  return std::visit(
      [&groups](auto&& arg) {
        if constexpr (std::is_same_v<std::decay_t<decltype(arg)>,
                                     std::vector<ASTNode>>) {
          for (ASTNode& child : arg) {
            GroupElementByASTType(child, groups);
          }
        }
      },
      astnode.children);
}

size_t ASTNode::NodeCount() const {
  return std::visit(
      [](auto&& arg) {
        size_t result = 1;  // count self.
        if constexpr (std::is_same_v<std::decay_t<decltype(arg)>,
                                     std::vector<ASTNode>>) {
          for (const ASTNode& child : arg) {
            result += child.NodeCount();
          }
        }
        return result;
      },
      children);
}

IRObject WrapASTIntoIRObject(const ASTNode& astnode, IRObject parsed_child) {
  IRObject obj;
  auto& subs = obj.MutableSubs();
  subs.push_back(IRObject::FromCorpus(astnode.type_id));
  subs.push_back(IRObject::FromCorpus(astnode.children.index()));
  subs.emplace_back(parsed_child);
  return obj;
}

}  // namespace fuzztest::internal::grammar
