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

#ifndef THIRD_PARTY_CENTIPEDE_EARLY_EXIT_H_
#define THIRD_PARTY_CENTIPEDE_EARLY_EXIT_H_

namespace centipede {
// Requests that the process exits soon, with `exit_code`.
// `exit_code` must be non-zero (!= EXIT_SUCCESS).
// Async-signal-safe.
void RequestEarlyExit(int exit_code);
// Returns true iff RequestEarlyExit() was called.
bool EarlyExitRequested();
// Returns the value most recently passed to RequestEarlyExit()
// or 0 if RequestEarlyExit() was not called.
int ExitCode();
}  // namespace centipede

#endif
