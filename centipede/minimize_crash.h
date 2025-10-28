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

#ifndef THIRD_PARTY_CENTIPEDE_MINIMIZE_CRASH_H_
#define THIRD_PARTY_CENTIPEDE_MINIMIZE_CRASH_H_

#include "absl/status/statusor.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/crash_deduplication.h"
#include "./centipede/environment.h"
#include "./common/defs.h"

namespace fuzztest::internal {

// Tries to minimize `crashy_input`.
// Uses `callbacks_factory` to create `env.num_threads` workers.
// Returns the details of a minimized crash if a smaller crash is found.
// Otherwise an error status is returned. Any smaller crash inputs found in the
// process will be stored in the crash reproducer directory of this shard.
absl::StatusOr<CrashDetails> MinimizeCrash(
    ByteSpan crashy_input, const Environment& env,
    CentipedeCallbacksFactory& callbacks_factory,
    const std::string* crash_signature, std::string_view output_dir);

}  // namespace fuzztest::internal

#endif  // THIRD_PARTY_CENTIPEDE_MINIMIZE_CRASH_H_
