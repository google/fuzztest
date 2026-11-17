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

//! The traits that a test framework implements to be driven by the FuzzTest engine.
//!
//! They mirror the callback tables of `engine_abi.h`. The engine calls the methods one at a
//! time, on the thread that called [`run_worker_if_requested`](crate::run_worker_if_requested).
//! A method runs inside an `extern "C"` callback, so a panic that unwinds out of it aborts the
//! process.

use crate::CoverageDomainRegistry;
use crate::ExecuteContext;
use crate::FeedbackSink;
use std::fmt::Debug;

/// Identifies one test to the engine, and constructs its adapters.
///
/// Corresponds to `FuzzTestAdapterManager` in `engine_abi.h`.
pub trait AdapterManager {
    /// The adapter of the test.
    type Adapter: Adapter;

    /// Returns the ID of the current binary.
    fn binary_id(&self) -> Vec<u8>;

    /// Returns the name of the test.
    fn test_name(&self) -> String;

    /// Constructs an adapter of the test.
    fn construct_adapter(&self) -> Self::Adapter;
}

/// The operations that the engine needs on the inputs of one test.
///
/// Corresponds to `FuzzTestAdapter` in `engine_abi.h`. The optional callbacks of that table
/// (preset seeds, cross-over and input metadata) have no method here yet, and the engine uses
/// its fallback for them.
///
/// An error that a method returns is reported to the engine as an unrecoverable error.
pub trait Adapter {
    /// An in-memory input of the test.
    ///
    /// The engine keeps the inputs that the adapter returns and passes them back by reference.
    /// An input is dropped when the engine is done with it.
    type Input;

    /// Why an operation failed. It is reported to the engine in its `Debug` format.
    type Error: Debug;

    /// Registers the coverage domains of the test with `registry`.
    ///
    /// The registrations must be the same for all the adapters of the same test.
    fn set_up_coverage_domains(&self, registry: &CoverageDomainRegistry);

    /// Returns a randomly generated seed input.
    fn random_seed_input(&self) -> Result<Self::Input, Self::Error>;

    /// Returns a mutant of `origin`, a smaller one if `shrink` is set.
    fn mutate(&self, origin: &Self::Input, shrink: bool) -> Result<Self::Input, Self::Error>;

    /// Executes `input` for testing. Emits the feedback of the execution to `feedback`, and
    /// reports its findings through `cx`.
    fn execute(&self, cx: &ExecuteContext<'_>, input: &Self::Input, feedback: &FeedbackSink);

    /// Serializes the content of `input`.
    fn serialize_input(&self, input: &Self::Input) -> Result<Vec<u8>, Self::Error>;

    /// Deserializes an input from its serialized `content`.
    fn deserialize_input(&self, content: &[u8]) -> Result<Self::Input, Self::Error>;
}
