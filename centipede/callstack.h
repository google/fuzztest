// Copyright 2023 The Centipede Authors.
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

#ifndef THIRD_PARTY_CENTIPEDE_CALLSTACK_H_
#define THIRD_PARTY_CENTIPEDE_CALLSTACK_H_

#include <cstddef>
#include <cstdint>

namespace centipede {
// CallStack maintains a function call stack for the current thread.
// It is told when a function is called, via OnFunctionEntry(pc, sp).
// It is not told when a function exits, so every time a new function is called
// it needs to unwind the stack based on the current and recorded sp values.
//
// This does not produce precise call stacks.
//
// For example, at some point the stack is:
// PC: 1, 2, 3
// SP: 10, 9, 8
// Then, functions 2 and 3 exit, and function 4 with a large stack is called:
// PC: 1, 4
// SP: 10, 7
// We will fail to unwind functions 2 and 3 and the stack will look like
// PC: 1, 2, 3, 4
// SP: 10, 9, 8, 7
//
// We currently don't see a reliable way to implement precise call stack by just
// observing function entries (and not exist).
// But for the purposes of Centipede (capturing call stacks as features) this
// implementation should be good enough.
//
// Alternatives that would allow collecting precise calls stacks are
// * add instrumentation to capture function exits
//  (fragile in presence of exceptions and longjmp).
// * unwind stack with frame pointers (expensive and also fragile).
// * Wait for hardware shadow call stacks (CET, etc).
//
// Function calls with depth beyond `kMaxDepth` will be ignored.
// Objects of this class must be created as global or TLS.
// The typical non-test usage is to create on TLS.
// There is no CTOR, the objects are zero-initialized.
// We currently do not use a CTOR with absl::ConstInitType so that the objects
// can be declared as __thread.
//
// This code assumes that the stack grows down.
template <size_t kMaxDepth = (1 << 12)>
class CallStack {
 public:
  // Returns the depth of the call stack.
  // May be less than the actual depth if that is greater than kMaxDepth.
  size_t Depth() const { return depth_; }

  // Returns the PC at `idx`, idx must be less than the current depth.
  uintptr_t PC(size_t idx) const {
    if (idx >= depth_) __builtin_trap();
    return pc_[idx];
  }

  // Updates the call stack on function entry.
  // `pc` is the function PC to be recorded.
  // `sp` is the current stack pointer value, which grows down.
  void OnFunctionEntry(uintptr_t pc, uintptr_t sp) {
    // First, unwind until the last record's SP is above `sp`.
    while (depth_) {
      if (sp_[depth_ - 1] <= sp)
        --depth_;
      else
        break;
    }
    // Ignore this call if we are already too deep.
    if (depth_ == kMaxDepth) return;
    // Record the frame.
    pc_[depth_] = pc;
    sp_[depth_] = sp;
    ++depth_;
  }

 private:
  // All data fields are zero initialized at process or thread startup.
  size_t depth_;
  uintptr_t pc_[kMaxDepth];
  uintptr_t sp_[kMaxDepth];
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_CALLSTACK_H_
