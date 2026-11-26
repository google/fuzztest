// Copyright 2026 Google LLC
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

#include "./framework_shared/sancov_runtime.h"

#include <pthread.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "./centipede/engine_abi.h"
#include "./centipede/feature.h"

extern "C" void __sanitizer_cov_stack_depth(void);
extern "C" void __sanitizer_cov_trace_const_cmp2(uint16_t arg1, uint16_t arg2);

namespace {

struct ClearStackLimitCallbackOnExit {
  ~ClearStackLimitCallbackOnExit() {
    SanCovRuntimeSetStackLimitCallback(nullptr);
  }
};

struct RestoreTracedOnExit {
  explicit RestoreTracedOnExit(bool old_traced) : old_traced(old_traced) {}
  ~RestoreTracedOnExit() { SanCovRuntimeSetCurrentThreadTraced(old_traced); }
  bool old_traced;
};

std::atomic<int> g_callback1_sync_calls{0};
std::atomic<int> g_callback1_post_calls{0};
std::atomic<size_t> g_callback1_max_sync_stack_usage{0};
std::atomic<int> g_callback2_sync_calls{0};
std::atomic<int> g_callback2_post_calls{0};

void StackLimitCallback1(size_t stack_usage, bool is_current_stack) {
  if (is_current_stack) {
    g_callback1_sync_calls.fetch_add(1, std::memory_order_relaxed);
    size_t prev =
        g_callback1_max_sync_stack_usage.load(std::memory_order_relaxed);
    while (stack_usage > prev &&
           !g_callback1_max_sync_stack_usage.compare_exchange_weak(
               prev, stack_usage, std::memory_order_relaxed)) {
    }
  } else {
    g_callback1_post_calls.fetch_add(1, std::memory_order_relaxed);
  }
}

void StackLimitCallback2(size_t /*stack_usage*/, bool is_current_stack) {
  if (is_current_stack) {
    g_callback2_sync_calls.fetch_add(1, std::memory_order_relaxed);
  } else {
    g_callback2_post_calls.fetch_add(1, std::memory_order_relaxed);
  }
}

__attribute__((noinline)) void TriggerStackDepthCallback(int depth) {
  volatile uint8_t frame_padding[256];
  frame_padding[0] = static_cast<uint8_t>(depth);
  if (depth > 0) {
    TriggerStackDepthCallback(depth - 1);
  } else {
    __sanitizer_cov_stack_depth();
  }
  // Keep `frame_padding` live across the call to prevent tail-call optimization
  // so SP drops below `tls.top_frame_sp` captured during static initialization.
  (void)frame_padding[0];
}

TEST(SanCovRuntimeTest, SetStackLimitCallbackSetReplaceAndClear) {
  ClearStackLimitCallbackOnExit cleanup;
  RestoreTracedOnExit restore_traced(SanCovRuntimeSetCurrentThreadTraced(true));
  g_callback1_sync_calls.store(0, std::memory_order_relaxed);
  g_callback1_post_calls.store(0, std::memory_order_relaxed);
  g_callback1_max_sync_stack_usage.store(0, std::memory_order_relaxed);
  g_callback2_sync_calls.store(0, std::memory_order_relaxed);
  g_callback2_post_calls.store(0, std::memory_order_relaxed);

  SanCovRuntimeSetStackLimitCallback(StackLimitCallback1);
  SanCovRuntimeClearCoverage(/*full_clear=*/true);
  TriggerStackDepthCallback(/*depth=*/256);
  SanCovRuntimePostProcessCoverage(/*reject_input=*/false);
  const int cb1_sync_calls_after_first_run =
      g_callback1_sync_calls.load(std::memory_order_relaxed);
  const int cb1_post_calls_after_first_run =
      g_callback1_post_calls.load(std::memory_order_relaxed);
  EXPECT_GT(cb1_sync_calls_after_first_run, 0);
  EXPECT_GT(g_callback1_max_sync_stack_usage.load(std::memory_order_relaxed),
            0);
  EXPECT_GT(cb1_post_calls_after_first_run, 0);

  SanCovRuntimeSetStackLimitCallback(StackLimitCallback2);
  SanCovRuntimeClearCoverage(/*full_clear=*/true);
  TriggerStackDepthCallback(/*depth=*/256);
  SanCovRuntimePostProcessCoverage(/*reject_input=*/false);
  EXPECT_EQ(g_callback1_sync_calls.load(std::memory_order_relaxed),
            cb1_sync_calls_after_first_run);
  EXPECT_EQ(g_callback1_post_calls.load(std::memory_order_relaxed),
            cb1_post_calls_after_first_run);
  const int cb2_sync_calls_after_replace =
      g_callback2_sync_calls.load(std::memory_order_relaxed);
  const int cb2_post_calls_after_replace =
      g_callback2_post_calls.load(std::memory_order_relaxed);
  EXPECT_GT(cb2_sync_calls_after_replace, 0);
  EXPECT_GT(cb2_post_calls_after_replace, 0);

  SanCovRuntimeSetStackLimitCallback(nullptr);
  SanCovRuntimeClearCoverage(/*full_clear=*/true);
  TriggerStackDepthCallback(/*depth=*/256);
  SanCovRuntimePostProcessCoverage(/*reject_input=*/false);
  EXPECT_EQ(g_callback1_sync_calls.load(std::memory_order_relaxed),
            cb1_sync_calls_after_first_run);
  EXPECT_EQ(g_callback1_post_calls.load(std::memory_order_relaxed),
            cb1_post_calls_after_first_run);
  EXPECT_EQ(g_callback2_sync_calls.load(std::memory_order_relaxed),
            cb2_sync_calls_after_replace);
  EXPECT_EQ(g_callback2_post_calls.load(std::memory_order_relaxed),
            cb2_post_calls_after_replace);
}

struct IgnoredThreadSync {
  pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
  pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
  int phase = 0;

  void AdvanceTo(int next_phase) {
    pthread_mutex_lock(&mu);
    phase = next_phase;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mu);
  }

  void WaitFor(int target_phase) {
    pthread_mutex_lock(&mu);
    while (phase < target_phase) {
      pthread_cond_wait(&cv, &mu);
    }
    pthread_mutex_unlock(&mu);
  }
};

void* IgnoredWorkerThread(void* arg) {
  auto* sync = static_cast<IgnoredThreadSync*>(arg);
  SanCovRuntimeSetCurrentThreadIgnored(true);
  sync->AdvanceTo(1);
  sync->WaitFor(2);

  __sanitizer_cov_trace_const_cmp2(0x1122, 0x3344);
  sync->AdvanceTo(3);
  sync->WaitFor(4);

  SanCovRuntimeSetCurrentThreadIgnored(false);
  sync->AdvanceTo(5);
  sync->WaitFor(6);
  return nullptr;
}

TEST(SanCovRuntimeTest, SetCurrentThreadIgnoredExcludesThreadFromPostProcess) {
  ClearStackLimitCallbackOnExit cleanup;
  g_callback1_post_calls.store(0, std::memory_order_relaxed);
  SanCovRuntimeSetStackLimitCallback(StackLimitCallback1);

  IgnoredThreadSync sync;
  pthread_t worker;
  ASSERT_EQ(pthread_create(&worker, nullptr, IgnoredWorkerThread, &sync), 0);

  // Wait until the worker marks itself ignored, then clear coverage so the
  // worker's CMP trace is the only coverage collected.
  sync.WaitFor(1);
  SanCovRuntimeClearCoverage(/*full_clear=*/true);
  sync.AdvanceTo(2);

  // While the worker is ignored, post-processing skips its TLS.
  sync.WaitFor(3);
  g_callback1_post_calls.store(0, std::memory_order_relaxed);
  SanCovRuntimePostProcessCoverage(/*reject_input=*/false);
  EXPECT_EQ(SanCovRuntimeGetCmpData().size, 0);
  const int calls_while_ignored =
      g_callback1_post_calls.load(std::memory_order_relaxed);
  EXPECT_GT(calls_while_ignored, 0);

  // Once the worker clears `ignored`, post-processing visits its TLS.
  sync.AdvanceTo(4);
  sync.WaitFor(5);
  g_callback1_post_calls.store(0, std::memory_order_relaxed);
  SanCovRuntimePostProcessCoverage(/*reject_input=*/false);
  EXPECT_GT(SanCovRuntimeGetCmpData().size, 0);
  EXPECT_EQ(g_callback1_post_calls.load(std::memory_order_relaxed),
            calls_while_ignored + 1);

  sync.AdvanceTo(6);
  ASSERT_EQ(pthread_join(worker, nullptr), 0);
  SanCovRuntimeClearCoverage(/*full_clear=*/true);
}

TEST(SanCovRuntimeTest, GetRawFeaturesAndGetCmpDataReflectPostProcess) {
  const bool old_traced = SanCovRuntimeSetCurrentThreadTraced(true);
  RestoreTracedOnExit restore_traced(old_traced);

  // Tracing disabled suppresses feature and CMP metadata capture.
  EXPECT_TRUE(SanCovRuntimeSetCurrentThreadTraced(false));
  SanCovRuntimeClearCoverage(/*full_clear=*/true);
  __sanitizer_cov_trace_const_cmp2(0x1234, 0x5678);
  SanCovRuntimePostProcessCoverage(/*reject_input=*/false);
  EXPECT_EQ(SanCovRuntimeGetRawFeatures().num_features, 0);
  EXPECT_EQ(SanCovRuntimeGetCmpData().size, 0);

  // Tracing re-enabled captures CMP features and serialized CMP metadata.
  EXPECT_FALSE(SanCovRuntimeSetCurrentThreadTraced(true));
  SanCovRuntimeClearCoverage(/*full_clear=*/true);
  const uint16_t lhs = 0x1234;
  const uint16_t rhs = 0x5678;
  __sanitizer_cov_trace_const_cmp2(lhs, rhs);
  SanCovRuntimePostProcessCoverage(/*reject_input=*/false);

  const SanCovRuntimeRawFeatureParts raw_features =
      SanCovRuntimeGetRawFeatures();
  EXPECT_NE(raw_features.features, nullptr);
  EXPECT_GT(raw_features.num_features, 0);

  const FuzzTestBytesView cmp_data = SanCovRuntimeGetCmpData();
  ASSERT_EQ(cmp_data.size, 1 + 2 * sizeof(uint16_t));
  EXPECT_EQ(cmp_data.data[0], sizeof(uint16_t));
  uint16_t decoded_lhs = 0;
  uint16_t decoded_rhs = 0;
  std::memcpy(&decoded_lhs, cmp_data.data + 1, sizeof(uint16_t));
  std::memcpy(&decoded_rhs, cmp_data.data + 1 + sizeof(uint16_t),
              sizeof(uint16_t));
  EXPECT_EQ(decoded_lhs, lhs);
  EXPECT_EQ(decoded_rhs, rhs);

  // Rejecting the input clears both raw features and CMP metadata.
  SanCovRuntimePostProcessCoverage(/*reject_input=*/true);
  EXPECT_EQ(SanCovRuntimeGetRawFeatures().num_features, 0);
  EXPECT_EQ(SanCovRuntimeGetCmpData().size, 0);
}

TEST(SanCovRuntimeTest, ConvertToEngineFeaturesEncodesRegularAndScoreFeatures) {
  namespace fd = fuzztest::internal::feature_domains;

  // Empty conversion should be a no-op.
  SanCovRuntimeConvertToEngineFeatures(nullptr, 0);

  constexpr uint64_t kPcIndex = 0x12345;
  constexpr uint64_t kCmpFeatureId = 0x42;
  constexpr uint64_t kCmpScore = 0x15;
  static_assert(kCmpScore <= fd::kCMPScoreBitmask);

  uint64_t features[2] = {
      fd::kPCs.ConvertToMe(kPcIndex),
      fd::kCMPModDiff.ConvertToMe((kCmpFeatureId << fd::kCMPScoreBits) |
                                  kCmpScore),
  };
  SanCovRuntimeConvertToEngineFeatures(features, 2);

  const auto domain_of = [](uint64_t f) {
    return (f >> kFuzzTestCoverageDomainIdStartBit) &
           ((uint64_t{1} << kFuzzTestCoverageDomainIdBitSize) - 1);
  };
  const auto id_of = [](uint64_t f) {
    return (f >> kFuzzTestCoverageFeatureIdStartBit) &
           ((uint64_t{1} << kFuzzTestCoverageFeatureIdBitSize) - 1);
  };
  const auto counter_of = [](uint64_t f) {
    return (f >> kFuzzTestCoverageCounterStartBit) &
           ((uint64_t{1} << kFuzzTestCoverageCounterBitSize) - 1);
  };

  EXPECT_EQ(domain_of(features[0]), fd::kPCs.domain_id());
  EXPECT_EQ(id_of(features[0]), kPcIndex);
  EXPECT_EQ(counter_of(features[0]), 0);

  EXPECT_EQ(domain_of(features[1]), fd::kCMPModDiff.domain_id());
  EXPECT_EQ(id_of(features[1]), kCmpFeatureId);
  EXPECT_EQ(counter_of(features[1]), kCmpScore);
}

TEST(SanCovRuntimeTest, SetUpCoverageDomainsRegistersDescriptiveNames) {
  namespace fd = fuzztest::internal::feature_domains;

  struct RegisteredDomain {
    uint8_t domain_id;
    std::string name;
    uint8_t feature_id_bit_size;
    uint8_t counter_bit_size;
  };
  std::vector<RegisteredDomain> registered;

  const FuzzTestCoverageDomainRegistry registry = {
      /*ctx=*/reinterpret_cast<FuzzTestCoverageDomainRegistryCtx*>(&registered),
      /*Register=*/
      [](FuzzTestCoverageDomainRegistryCtx* ctx,
         const FuzzTestCoverageDomain* domain) {
        auto* out = reinterpret_cast<std::vector<RegisteredDomain>*>(ctx);
        out->push_back({
            domain->domain_id,
            std::string(reinterpret_cast<const char*>(domain->name.data),
                        domain->name.size),
            domain->feature_id_bit_size,
            domain->counter_bit_size,
        });
      },
  };

  EXPECT_EQ(SanCovRuntimeSetUpCoverageDomains(&registry), fd::kNumDomains);
  ASSERT_EQ(registered.size(), fd::kNumDomains);
  for (size_t i = 0; i < fd::kNumDomains; ++i) {
    EXPECT_EQ(registered[i].domain_id, i);
    EXPECT_FALSE(registered[i].name.empty());
  }
  EXPECT_EQ(registered[fd::kUnknown.domain_id()].name, "unknown");
  EXPECT_EQ(registered[fd::kPCs.domain_id()].name, "pcs");
  EXPECT_EQ(registered[fd::kPCs.domain_id()].counter_bit_size, 0);
  EXPECT_EQ(registered[fd::k8bitCounters.domain_id()].name, "8bit_counters");
  EXPECT_EQ(registered[fd::kCMPModDiff.domain_id()].name, "cmp_mod_diff");
  EXPECT_EQ(registered[fd::kCMPModDiff.domain_id()].counter_bit_size,
            fd::kCMPScoreBits);
  EXPECT_EQ(registered[fd::kUserDomains.front().domain_id()].name, "user0");
  EXPECT_EQ(registered[fd::kUserDomains.back().domain_id()].name, "user15");
}

}  // namespace
