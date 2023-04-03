// Copyright 2022 The Centipede Authors.
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

#ifndef THIRD_PARTY_CENTIPEDE_BINARY_INFO_H_
#define THIRD_PARTY_CENTIPEDE_BINARY_INFO_H_

#include "./centipede/call_graph.h"
#include "./centipede/control_flow.h"
#include "./centipede/symbol_table.h"

namespace centipede {

// Information about the binary being fuzzed. Created once at program startup
// and doesn't change (other than for lazily initialized fields).
struct BinaryInfo {
  PCTable pc_table;
  SymbolTable symbols;
  CFTable cf_table;
  ControlFlowGraph control_flow_graph;
  CallGraph call_graph;
  bool uses_legacy_trace_pc_instrumentation = false;
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_BINARY_INFO_H_
