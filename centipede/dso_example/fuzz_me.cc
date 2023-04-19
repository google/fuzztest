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

// An example of a fuzz target that resides in a separate DSO.

#include <cstddef>
#include <cstdint>

extern "C" void FuzzMe(const uint8_t *data, size_t size) {
  if (size == 3 && data[0] == 'F' && data[1] == 'U' && data[2] == 'Z')
    __builtin_trap();
}
