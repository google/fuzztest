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
  kESCAPEDNode,
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
  kElementsSubNode6,
  kSTRINGSubNode7,
  kSTRINGSubNode9,
  kSTRINGSubNode8,
  kNUMBERSubNode10,
  kNUMBERSubNode11,
  kINTEGERSubNode12,
  kINTEGERSubNode13,
  kINTEGERSubNode14,
  kDIGITSSubNode15,
  kEXPONENTSubNode16,
  kEXPONENTSubNode17,
  kWSPACESubNode18,
  kLiteral14,
  kLiteral18,
  kLiteral15,
  kLiteral13,
  kLiteral6,
  kLiteral12,
  kLiteral3,
  kLiteral19,
  kLiteral4,
  kLiteral5,
  kLiteral20,
  kLiteral7,
  kLiteral8,
  kLiteral1,
  kLiteral9,
  kLiteral2,
  kLiteral10,
  kLiteral11,
  kLiteral0,
  kLiteral16,
  kLiteral17,
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
class ESCAPEDNode;
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
class ElementsSubNode6;
class STRINGSubNode7;
class STRINGSubNode9;
class STRINGSubNode8;
class NUMBERSubNode10;
class NUMBERSubNode11;
class INTEGERSubNode12;
class INTEGERSubNode13;
class INTEGERSubNode14;
class DIGITSSubNode15;
class EXPONENTSubNode16;
class EXPONENTSubNode17;
class WSPACESubNode18;
class Literal14;
class Literal18;
class Literal15;
class Literal13;
class Literal6;
class Literal12;
class Literal3;
class Literal19;
class Literal4;
class Literal5;
class Literal20;
class Literal7;
class Literal8;
class Literal1;
class Literal9;
class Literal2;
class Literal10;
class Literal11;
class Literal0;
class Literal16;
class Literal17;
class CharSet3;
class CharSet1;
class CharSet2;
class CharSet0;

inline constexpr absl::string_view kStrLiteral14 = "+";
inline constexpr absl::string_view kStrLiteral18 = ",";
inline constexpr absl::string_view kStrLiteral15 = "-";
inline constexpr absl::string_view kStrLiteral13 = ".";
inline constexpr absl::string_view kStrLiteral6 = "/";
inline constexpr absl::string_view kStrLiteral12 = "0";
inline constexpr absl::string_view kStrLiteral3 = ":";
inline constexpr absl::string_view kStrLiteral19 = "[";
inline constexpr absl::string_view kStrLiteral4 = "\"";
inline constexpr absl::string_view kStrLiteral5 = "\\";
inline constexpr absl::string_view kStrLiteral20 = "]";
inline constexpr absl::string_view kStrLiteral7 = "b";
inline constexpr absl::string_view kStrLiteral8 = "f";
inline constexpr absl::string_view kStrLiteral1 = "false";
inline constexpr absl::string_view kStrLiteral9 = "n";
inline constexpr absl::string_view kStrLiteral2 = "null";
inline constexpr absl::string_view kStrLiteral10 = "r";
inline constexpr absl::string_view kStrLiteral11 = "t";
inline constexpr absl::string_view kStrLiteral0 = "true";
inline constexpr absl::string_view kStrLiteral16 = "{";
inline constexpr absl::string_view kStrLiteral17 = "}";
inline constexpr absl::string_view kStrCharSet3 = R"grammar([ \t\n\r])grammar";
inline constexpr absl::string_view kStrCharSet1 = R"grammar([1-9])grammar";
inline constexpr absl::string_view kStrCharSet2 = R"grammar([Ee])grammar";
inline constexpr absl::string_view kStrCharSet0 =
    R"grammar([a-zA-Z0-9_])grammar";

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
    : public TupleDomain<kElementsNode, ElementNode, ElementsSubNode5> {};
class ElementNode final : public TupleDomain<kElementNode, ValueNode> {};
class STRINGNode final
    : public TupleDomain<kSTRINGNode, Literal4, STRINGSubNode7, Literal4> {};
class CHARACTERNode final : public TupleDomain<kCHARACTERNode, CharSet0> {};
class ESCAPEDNode final
    : public VariantDomain<kESCAPEDNode, 0, Literal4, Literal5, Literal6,
                           Literal7, Literal8, Literal9, Literal10, Literal11> {
};
class NUMBERNode final : public TupleDomain<kNUMBERNode, INTEGERNode,
                                            NUMBERSubNode10, NUMBERSubNode11> {
};
class INTEGERNode final
    : public VariantDomain<kINTEGERNode, 0, DIGITNode, INTEGERSubNode12,
                           INTEGERSubNode13, INTEGERSubNode14> {};
class DIGITSNode final : public TupleDomain<kDIGITSNode, DIGITSSubNode15> {};
class DIGITNode final
    : public VariantDomain<kDIGITNode, 0, Literal12, ONETONINENode> {};
class ONETONINENode final : public TupleDomain<kONETONINENode, CharSet1> {};
class FRACTIONNode final
    : public TupleDomain<kFRACTIONNode, Literal13, DIGITSNode> {};
class EXPONENTNode final
    : public TupleDomain<kEXPONENTNode, CharSet2, EXPONENTSubNode16,
                         ONETONINENode, EXPONENTSubNode17> {};
class SIGNNode final
    : public VariantDomain<kSIGNNode, 0, Literal14, Literal15> {};
class WSPACENode final : public TupleDomain<kWSPACENode, WSPACESubNode18> {};
class ObjectSubNode0 final
    : public TupleDomain<kObjectSubNode0, Literal16, Literal17> {};
class ObjectSubNode1 final
    : public TupleDomain<kObjectSubNode1, Literal16, MembersNode, Literal17> {};
class MembersSubNode2 final
    : public TupleDomain<kMembersSubNode2, MemberNode, Literal18, MembersNode> {
};
class ArraySubNode3 final
    : public TupleDomain<kArraySubNode3, Literal19, Literal20> {};
class ArraySubNode4 final
    : public TupleDomain<kArraySubNode4, Literal19, ElementsNode, Literal20> {};
class ElementsSubNode5 final
    : public Vector<kElementsSubNode5, ElementsSubNode6> {};
class ElementsSubNode6 final
    : public TupleDomain<kElementsSubNode6, Literal18, ElementNode> {};
class STRINGSubNode7 final : public Vector<kSTRINGSubNode7, STRINGSubNode8> {};
class STRINGSubNode9 final
    : public TupleDomain<kSTRINGSubNode9, Literal5, ESCAPEDNode> {};
class STRINGSubNode8 final
    : public VariantDomain<kSTRINGSubNode8, 0, CHARACTERNode, STRINGSubNode9> {
};
class NUMBERSubNode10 final : public Optional<kNUMBERSubNode10, FRACTIONNode> {
};
class NUMBERSubNode11 final : public Optional<kNUMBERSubNode11, EXPONENTNode> {
};
class INTEGERSubNode12 final
    : public TupleDomain<kINTEGERSubNode12, ONETONINENode, DIGITSNode> {};
class INTEGERSubNode13 final
    : public TupleDomain<kINTEGERSubNode13, Literal15, DIGITNode> {};
class INTEGERSubNode14 final : public TupleDomain<kINTEGERSubNode14, Literal15,
                                                  ONETONINENode, DIGITSNode> {};
class DIGITSSubNode15 final
    : public NonEmptyVector<kDIGITSSubNode15, DIGITNode> {};
class EXPONENTSubNode16 final : public Optional<kEXPONENTSubNode16, SIGNNode> {
};
class EXPONENTSubNode17 final : public Optional<kEXPONENTSubNode17, DIGITNode> {
};
class WSPACESubNode18 final
    : public NonEmptyVector<kWSPACESubNode18, CharSet3> {};
class Literal14 final : public StringLiteralDomain<kLiteral14, kStrLiteral14> {
};
class Literal18 final : public StringLiteralDomain<kLiteral18, kStrLiteral18> {
};
class Literal15 final : public StringLiteralDomain<kLiteral15, kStrLiteral15> {
};
class Literal13 final : public StringLiteralDomain<kLiteral13, kStrLiteral13> {
};
class Literal6 final : public StringLiteralDomain<kLiteral6, kStrLiteral6> {};
class Literal12 final : public StringLiteralDomain<kLiteral12, kStrLiteral12> {
};
class Literal3 final : public StringLiteralDomain<kLiteral3, kStrLiteral3> {};
class Literal19 final : public StringLiteralDomain<kLiteral19, kStrLiteral19> {
};
class Literal4 final : public StringLiteralDomain<kLiteral4, kStrLiteral4> {};
class Literal5 final : public StringLiteralDomain<kLiteral5, kStrLiteral5> {};
class Literal20 final : public StringLiteralDomain<kLiteral20, kStrLiteral20> {
};
class Literal7 final : public StringLiteralDomain<kLiteral7, kStrLiteral7> {};
class Literal8 final : public StringLiteralDomain<kLiteral8, kStrLiteral8> {};
class Literal1 final : public StringLiteralDomain<kLiteral1, kStrLiteral1> {};
class Literal9 final : public StringLiteralDomain<kLiteral9, kStrLiteral9> {};
class Literal2 final : public StringLiteralDomain<kLiteral2, kStrLiteral2> {};
class Literal10 final : public StringLiteralDomain<kLiteral10, kStrLiteral10> {
};
class Literal11 final : public StringLiteralDomain<kLiteral11, kStrLiteral11> {
};
class Literal0 final : public StringLiteralDomain<kLiteral0, kStrLiteral0> {};
class Literal16 final : public StringLiteralDomain<kLiteral16, kStrLiteral16> {
};
class Literal17 final : public StringLiteralDomain<kLiteral17, kStrLiteral17> {
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
