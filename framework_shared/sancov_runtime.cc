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

#include <string.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

#include "./centipede/engine_abi.h"
#include "./centipede/feature.h"
#include "./framework_shared/internal/sancov_state.h"

namespace {

// Left-shifts the first `size` bits of `value` by `shift_by`.
template <typename T>
constexpr T GetShiftedBits(T value, size_t size, size_t shift_by) {
  return (value & ((T{1} << size) - 1)) << shift_by;
}

struct SancovStateManager {
  SancovStateManager() { SanCovRuntimeInitialize(); }
};

SancovStateManager sancov_state_manager __attribute__((init_priority(200)));

}  // namespace

// Can be overridden to not depend explicitly on CENTIPEDE_RUNNER_FLAGS.
extern "C" __attribute__((weak)) const char* GetSancovFlags(void) {
  static const char* flags = []() -> const char* {
    if (const char* sancov_flags_env = std::getenv("CENTIPEDE_RUNNER_FLAGS")) {
      return strdup(sancov_flags_env);
    }
    return nullptr;
  }();
  return flags;
}

void SanCovRuntimeInitialize(void) {
  [[maybe_unused]] static bool construct_once = [] {
    fuzztest::internal::sancov_state.Construct(GetSancovFlags());
    return true;
  }();
}

void SanCovRuntimeSetStackLimitCallback(
    SanCovRuntimeStackLimitCallback callback) {
  fuzztest::internal::stack_limit_callback.store(callback,
                                                 std::memory_order_release);
}

bool SanCovRuntimeSetCurrentThreadTraced(bool traced) {
  const bool old_traced = fuzztest::internal::tls.traced;
  fuzztest::internal::tls.traced = traced;
  return old_traced;
}

void SanCovRuntimeSetCurrentThreadIgnored(bool ignored) {
  fuzztest::internal::LockGuard lock(
      fuzztest::internal::sancov_state->tls_list_mu);
  fuzztest::internal::tls.ignore = ignored;
}

void SanCovRuntimeClearCoverage(bool full_clear) {
  fuzztest::internal::CleanUpSancovTls();
  fuzztest::internal::PrepareSancov(full_clear);
}

struct SanCovRuntimeRawFeatureParts SanCovRuntimeGetRawFeatures(void) {
  return {fuzztest::internal::sancov_state->g_features.data(),
          fuzztest::internal::sancov_state->g_features.size()};
}

struct SanCovRuntimeRawFeatureParts SanCovRuntimeGetCoverage(
    bool reject_input) {
  SanCovRuntimePostProcessCoverage(reject_input);

  return SanCovRuntimeGetRawFeatures();
}

void SanCovRuntimeConvertToEngineFeatures(uint64_t* features,
                                          size_t num_features) {
  using ::fuzztest::internal::feature_domains::Domain;
  using ::fuzztest::internal::feature_domains::IsComparisonScoreFeature;
  using ::fuzztest::internal::feature_domains::kCMPScoreBitmask;
  using ::fuzztest::internal::feature_domains::kCMPScoreBits;

  for (size_t i = 0; i < num_features; ++i) {
    auto& feature = features[i];
    const auto domain_id = Domain::FeatureToDomainId(feature);
    auto feature_id = Domain::FeatureToIndexInDomain(feature);
    if (IsComparisonScoreFeature(feature)) {
      const auto counter = feature_id & kCMPScoreBitmask;
      feature_id >>= kCMPScoreBits;
      feature = GetShiftedBits(domain_id, kFuzzTestCoverageDomainIdBitSize,
                               kFuzzTestCoverageDomainIdStartBit) |
                GetShiftedBits(feature_id, kFuzzTestCoverageFeatureIdBitSize,
                               kFuzzTestCoverageFeatureIdStartBit) |
                GetShiftedBits(counter, kFuzzTestCoverageCounterBitSize,
                               kFuzzTestCoverageCounterStartBit);
      continue;
    }
    feature = GetShiftedBits(domain_id, kFuzzTestCoverageDomainIdBitSize,
                             kFuzzTestCoverageDomainIdStartBit) |
              GetShiftedBits(feature_id, kFuzzTestCoverageFeatureIdBitSize,
                             kFuzzTestCoverageFeatureIdStartBit);
  }
}

FuzzTestBytesView SanCovRuntimeGetCmpData(void) {
  const auto& cmp_data = fuzztest::internal::sancov_state->metadata.cmp_data;
  return {cmp_data.data(), cmp_data.size()};
}

size_t SanCovRuntimeSetUpCoverageDomains(
    const FuzzTestCoverageDomainRegistry* registry) {
  using ::fuzztest::internal::feature_domains::Domain;
  using ::fuzztest::internal::feature_domains::kCMPScoreBits;
  using ::fuzztest::internal::feature_domains::kCMPScoreDomains;
  using ::fuzztest::internal::feature_domains::kNumDomains;

  static_assert(Domain::kDomainSize == 1 << 27);
  static_assert(kNumDomains <= 100);
  static_assert(kCMPScoreBits <= 27);
  static_assert(kCMPScoreBits <= kFuzzTestCoverageCounterBitSize);

  for (size_t domain_id = 0; domain_id < kNumDomains; ++domain_id) {
    const bool is_scoring_domain =
        domain_id >= kCMPScoreDomains.front().domain_id() &&
        domain_id <= kCMPScoreDomains.back().domain_id();
    std::string domain_name = "dom";
    domain_name += '0' + domain_id / 10;
    domain_name += '0' + domain_id % 10;
    const FuzzTestCoverageDomain domain = {
        static_cast<uint8_t>(domain_id),
        FuzzTestBytesView{
            reinterpret_cast<const uint8_t*>(domain_name.data()),
            domain_name.size(),
        },
        /*feature_id_bit_size=*/
        static_cast<uint8_t>(is_scoring_domain ? 27 - kCMPScoreBits : 27),
        /*counter_bit_size=*/
        static_cast<uint8_t>(is_scoring_domain ? kCMPScoreBits : 0),
    };
    registry->Register(registry->ctx, &domain);
  }

  return kNumDomains;
}

void SanCovRuntimePostProcessCoverage(bool reject_input) {
  fuzztest::internal::PostProcessSancov(reject_input);
}

void SanCovRuntimeEmitFeatures(const FuzzTestFeedbackSink* sink) {
  using ::fuzztest::internal::sancov_state;

  SanCovRuntimeConvertToEngineFeatures(sancov_state->g_features.data(),
                                       sancov_state->g_features.size());
  const FuzzTestUint64sView features = {
      sancov_state->g_features.data(),
      sancov_state->g_features.size(),
  };
  sink->EmitCoverageFeatures(sink->ctx, &features);
  sancov_state->g_features.clear();
}
