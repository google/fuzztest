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

#ifndef THIRD_PARTY_CENTIPEDE_LOGGING_H_
#define THIRD_PARTY_CENTIPEDE_LOGGING_H_

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/flags/flag.h"  // absl::GetFlag
#include "absl/flags/declare.h"  // ABSL_DECLARE_FLAG

ABSL_DECLARE_FLAG(int, v);

#define VLOG_IS_ON(logging_level) ((logging_level) <= absl::GetFlag(FLAGS_v))
#define VLOG(logging_level) LOG_IF(INFO, VLOG_IS_ON(logging_level))

// Easy variable value logging: LOG(INFO) << VV(foo) << VV(bar);
#define VV(x) #x ": " << (x) << " "

#endif  // THIRD_PARTY_CENTIPEDE_LOGGING_H_
