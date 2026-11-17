// Copyright 2026 Google LLC
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

#![deny(clippy::absolute_paths)]
#![deny(unused_imports)]
#![deny(unsafe_op_in_unsafe_fn)]

mod coverage;

pub use coverage::SanCovRuntimeRawFeatureParts;
use engine::{CoverageDomainRegistry, FeedbackSink};

pub fn prepare_coverage(full_clear: bool) {
    coverage::SanCovRuntimeClearCoverage(full_clear)
}

pub fn get_coverage(reject_input: bool) -> SanCovRuntimeRawFeatureParts {
    coverage::SanCovRuntimeGetCoverage(reject_input)
}

pub fn post_process_coverage(reject_input: bool) {
    coverage::SanCovRuntimePostProcessCoverage(reject_input)
}

/// Registers the SanitizerCoverage feature domains with `registry`.
pub fn set_up_coverage_domains(registry: &CoverageDomainRegistry) {
    coverage::set_up_coverage_domains(registry);
}

/// Emits post-processed SanitizerCoverage features into `feedback`.
pub fn emit_coverage_features(feedback: &FeedbackSink) {
    coverage::emit_coverage_features(feedback);
}
