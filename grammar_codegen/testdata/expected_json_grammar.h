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

#ifndef FUZZTEST_GRAMMARS_JSON_GRAMMAR_H_
#define FUZZTEST_GRAMMARS_JSON_GRAMMAR_H_

#include "./fuzztest/internal/domains/in_grammar_impl.h"

namespace fuzztest::internal::grammar::json {

enum JsonTypes {
  kJsonNode,
  kValueNode,
  kObjectNode,
  kMembersNode,
  kMemberNode,
  kArrayNode,
  kElementsNode,
  kElementNode,
  kSTRINGNode,
  kCHARACTERNode,
  kNUMBERNode,
  kINTEGERNode,
  kDIGITSNode,
  kDIGITNode,
  kONETONINENode,
  kFRACTIONNode,
  kEXPONENTNode,
  kSIGNNode,
  kWSPACENode,
  kObjectSubNode0,
  kObjectSubNode1,
  kMembersSubNode2,
  kArraySubNode3,
  kArraySubNode4,
  kElementsSubNode5,
  kSTRINGSubNode6,
  kNUMBERSubNode7,
  kNUMBERSubNode8,
  kINTEGERSubNode9,
  kINTEGERSubNode10,
  kINTEGERSubNode11,
  kDIGITSSubNode12,
  kEXPONENTSubNode13,
  kEXPONENTSubNode14,
  kWSPACESubNode15,
  kLiteral7,
  kLiteral11,
  kLiteral8,
  kLiteral6,
  kLiteral5,
  kLiteral3,
  kLiteral12,
  kLiteral4,
  kLiteral13,
  kLiteral1,
  kLiteral2,
  kLiteral0,
  kLiteral9,
  kLiteral10,
  kCharSet3,
  kCharSet1,
  kCharSet2,
  kCharSet0,
};
class JsonNode;
class ValueNode;
class ObjectNode;
class MembersNode;
class MemberNode;
class ArrayNode;
class ElementsNode;
class ElementNode;
class STRINGNode;
class CHARACTERNode;
class NUMBERNode;
class INTEGERNode;
class DIGITSNode;
class DIGITNode;
class ONETONINENode;
class FRACTIONNode;
class EXPONENTNode;
class SIGNNode;
class WSPACENode;
class ObjectSubNode0;
class ObjectSubNode1;
class MembersSubNode2;
class ArraySubNode3;
class ArraySubNode4;
class ElementsSubNode5;
class STRINGSubNode6;
class NUMBERSubNode7;
class NUMBERSubNode8;
class INTEGERSubNode9;
class INTEGERSubNode10;
class INTEGERSubNode11;
class DIGITSSubNode12;
class EXPONENTSubNode13;
class EXPONENTSubNode14;
class WSPACESubNode15;
class Literal7;
class Literal11;
class Literal8;
class Literal6;
class Literal5;
class Literal3;
class Literal12;
class Literal4;
class Literal13;
class Literal1;
class Literal2;
class Literal0;
class Literal9;
class Literal10;
class CharSet3;
class CharSet1;
class CharSet2;
class CharSet0;

inline constexpr absl::string_view kStrLiteral7 = "+";
inline constexpr absl::string_view kStrLiteral11 = ",";
inline constexpr absl::string_view kStrLiteral8 = "-";
inline constexpr absl::string_view kStrLiteral6 = ".";
inline constexpr absl::string_view kStrLiteral5 = "0";
inline constexpr absl::string_view kStrLiteral3 = ":";
inline constexpr absl::string_view kStrLiteral12 = "[";
inline constexpr absl::string_view kStrLiteral4 = "\"";
inline constexpr absl::string_view kStrLiteral13 = "]";
inline constexpr absl::string_view kStrLiteral1 = "false";
inline constexpr absl::string_view kStrLiteral2 = "null";
inline constexpr absl::string_view kStrLiteral0 = "true";
inline constexpr absl::string_view kStrLiteral9 = "{";
inline constexpr absl::string_view kStrLiteral10 = "}";
inline constexpr absl::string_view kStrCharSet3 = "[ \\t\\n\\r]";
inline constexpr absl::string_view kStrCharSet1 = "[1-9]";
inline constexpr absl::string_view kStrCharSet2 = "[Ee]";
inline constexpr absl::string_view kStrCharSet0 = "[a-zA-Z0-9_]";

class JsonNode final : public TupleDomain<kJsonNode, ElementNode> {};
class ValueNode final
    : public VariantDomain<kValueNode, 4, ObjectNode, ArrayNode, STRINGNode,
                           NUMBERNode, Literal0, Literal1, Literal2> {};
class ObjectNode final
    : public VariantDomain<kObjectNode, 0, ObjectSubNode0, ObjectSubNode1> {};
class MembersNode final
    : public VariantDomain<kMembersNode, 0, MemberNode, MembersSubNode2> {};
class MemberNode final
    : public TupleDomain<kMemberNode, STRINGNode, Literal3, ElementNode> {};
class ArrayNode final
    : public VariantDomain<kArrayNode, 0, ArraySubNode3, ArraySubNode4> {};
class ElementsNode final
    : public VariantDomain<kElementsNode, 0, ElementNode, ElementsSubNode5> {};
class ElementNode final : public TupleDomain<kElementNode, ValueNode> {};
class STRINGNode final
    : public TupleDomain<kSTRINGNode, Literal4, STRINGSubNode6, Literal4> {};
class CHARACTERNode final : public TupleDomain<kCHARACTERNode, CharSet0> {};
class NUMBERNode final : public TupleDomain<kNUMBERNode, INTEGERNode,
                                            NUMBERSubNode7, NUMBERSubNode8> {};
class INTEGERNode final
    : public VariantDomain<kINTEGERNode, 0, DIGITNode, INTEGERSubNode9,
                           INTEGERSubNode10, INTEGERSubNode11> {};
class DIGITSNode final : public TupleDomain<kDIGITSNode, DIGITSSubNode12> {};
class DIGITNode final
    : public VariantDomain<kDIGITNode, 0, Literal5, ONETONINENode> {};
class ONETONINENode final : public TupleDomain<kONETONINENode, CharSet1> {};
class FRACTIONNode final
    : public TupleDomain<kFRACTIONNode, Literal6, DIGITSNode> {};
class EXPONENTNode final
    : public TupleDomain<kEXPONENTNode, CharSet2, EXPONENTSubNode13,
                         ONETONINENode, EXPONENTSubNode14> {};
class SIGNNode final : public VariantDomain<kSIGNNode, 0, Literal7, Literal8> {
};
class WSPACENode final : public TupleDomain<kWSPACENode, WSPACESubNode15> {};
class ObjectSubNode0 final
    : public TupleDomain<kObjectSubNode0, Literal9, Literal10> {};
class ObjectSubNode1 final
    : public TupleDomain<kObjectSubNode1, Literal9, MembersNode, Literal10> {};
class MembersSubNode2 final
    : public TupleDomain<kMembersSubNode2, MemberNode, Literal11, MembersNode> {
};
class ArraySubNode3 final
    : public TupleDomain<kArraySubNode3, Literal12, Literal13> {};
class ArraySubNode4 final
    : public TupleDomain<kArraySubNode4, Literal12, ElementsNode, Literal13> {};
class ElementsSubNode5 final
    : public TupleDomain<kElementsSubNode5, ElementNode, Literal11,
                         ElementsNode> {};
class STRINGSubNode6 final : public Vector<kSTRINGSubNode6, CHARACTERNode> {};
class NUMBERSubNode7 final : public Optional<kNUMBERSubNode7, FRACTIONNode> {};
class NUMBERSubNode8 final : public Optional<kNUMBERSubNode8, EXPONENTNode> {};
class INTEGERSubNode9 final
    : public TupleDomain<kINTEGERSubNode9, ONETONINENode, DIGITSNode> {};
class INTEGERSubNode10 final
    : public TupleDomain<kINTEGERSubNode10, Literal8, DIGITNode> {};
class INTEGERSubNode11 final : public TupleDomain<kINTEGERSubNode11, Literal8,
                                                  ONETONINENode, DIGITSNode> {};
class DIGITSSubNode12 final
    : public NonEmptyVector<kDIGITSSubNode12, DIGITNode> {};
class EXPONENTSubNode13 final : public Optional<kEXPONENTSubNode13, SIGNNode> {
};
class EXPONENTSubNode14 final : public Optional<kEXPONENTSubNode14, DIGITNode> {
};
class WSPACESubNode15 final
    : public NonEmptyVector<kWSPACESubNode15, CharSet3> {};
class Literal7 final : public StringLiteralDomain<kLiteral7, kStrLiteral7> {};
class Literal11 final : public StringLiteralDomain<kLiteral11, kStrLiteral11> {
};
class Literal8 final : public StringLiteralDomain<kLiteral8, kStrLiteral8> {};
class Literal6 final : public StringLiteralDomain<kLiteral6, kStrLiteral6> {};
class Literal5 final : public StringLiteralDomain<kLiteral5, kStrLiteral5> {};
class Literal3 final : public StringLiteralDomain<kLiteral3, kStrLiteral3> {};
class Literal12 final : public StringLiteralDomain<kLiteral12, kStrLiteral12> {
};
class Literal4 final : public StringLiteralDomain<kLiteral4, kStrLiteral4> {};
class Literal13 final : public StringLiteralDomain<kLiteral13, kStrLiteral13> {
};
class Literal1 final : public StringLiteralDomain<kLiteral1, kStrLiteral1> {};
class Literal2 final : public StringLiteralDomain<kLiteral2, kStrLiteral2> {};
class Literal0 final : public StringLiteralDomain<kLiteral0, kStrLiteral0> {};
class Literal9 final : public StringLiteralDomain<kLiteral9, kStrLiteral9> {};
class Literal10 final : public StringLiteralDomain<kLiteral10, kStrLiteral10> {
};
class CharSet3 final : public RegexLiteralDomain<kCharSet3, kStrCharSet3> {};
class CharSet1 final : public RegexLiteralDomain<kCharSet1, kStrCharSet1> {};
class CharSet2 final : public RegexLiteralDomain<kCharSet2, kStrCharSet2> {};
class CharSet0 final : public RegexLiteralDomain<kCharSet0, kStrCharSet0> {};
}  // namespace fuzztest::internal::grammar::json
namespace fuzztest::internal_no_adl {

inline auto InJsonGrammar() {
  return internal::grammar::InGrammarImpl<internal::grammar::json::JsonNode>();
}

}  // namespace fuzztest::internal_no_adl
#endif  // FUZZTEST_GRAMMARS_JSON_GRAMMAR_H_
