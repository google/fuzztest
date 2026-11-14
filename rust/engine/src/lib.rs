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

//! A safe interface to the FuzzTest engine.
//!
//! A test framework implements [`AdapterManager`] and [`Adapter`], and gives the manager to
//! [`run_worker_if_requested`] or to [`run_controller`]. The `extern "C"` callbacks that the
//! engine calls, and the `unsafe` code that they need, stay inside this crate.
//!
//! A crash hook, which has no adapter at hand, reports a finding with [`try_emit_finding`].

#![deny(clippy::absolute_paths)]
#![deny(unused_imports)]
// The callbacks of `worker` are `unsafe` functions. An unsafe operation in their body still
// has to be written in an `unsafe` block, with a `SAFETY` comment of its own.
#![deny(unsafe_op_in_unsafe_fn)]

mod adapter;
mod diagnostics;
mod engine_ffi;
mod worker;

pub use adapter::Adapter;
pub use adapter::AdapterManager;
pub use diagnostics::try_emit_finding;
pub use diagnostics::ExecuteContext;
pub use engine_ffi::CoverageDomain;
pub use engine_ffi::FuzzTestCoverageDomainRegistry as CoverageDomainRegistry;
pub use engine_ffi::FuzzTestCoverageFeatureLayout as CoverageFeatureLayout;
pub use engine_ffi::FuzzTestFeedbackSink as FeedbackSink;
pub use worker::run_controller;
pub use worker::run_worker_if_requested;
pub use worker::RunOutcome;
