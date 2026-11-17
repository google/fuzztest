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

//! Runs the FuzzTest engine with an [`AdapterManager`].
//!
//! The engine drives a test through two tables of C callbacks, `FuzzTestAdapterManager` and
//! `FuzzTestAdapter`. This module fills them in with functions that forward to an
//! [`AdapterManager`] and to its [`Adapter`], so that a test framework needs no `unsafe` code.
//!
//! One adapter is alive at a time in a process: `ConstructAdapter` reports an error instead of
//! constructing a second one.
//!
//! The inputs of an adapter live in a [`safer_cffi::OpaqueTracker`]. The engine gets a
//! generational handle for each of them, and a handle that refers to no live input is reported
//! to the engine instead of being used.
//!
//! # Engine contract
//!
//! The callbacks are `unsafe` to call, because they rely on how the engine calls them.
//! `engine_abi.h` documents it, and the `SAFETY` comments of this module refer to these rules
//! by number:
//!
//! 1. The engine calls the callbacks of a manager, and of the adapter that it constructs, one at a
//!    time. It calls them on the thread that passed the manager to `FuzzTestWorkerMaybeRun` or
//!    `FuzzTestControllerRun`, and before that function returns.
//! 2. A pointer argument is null, or it meets until the callback returns what Rust requires of the
//!    reference that `engine_ffi` declares it as. A view, a sink or a registry that the engine
//!    passes upholds the safety invariant of its type, and calling it never calls a callback.
//! 3. A manager callback receives the `ctx` of the `FuzzTestAdapterManager` that holds it. An
//!    adapter callback receives the `ctx` of the `FuzzTestAdapter` that holds it, after
//!    `ConstructAdapter` filled that table in. Once the engine has called `FreeCtx`, it calls
//!    nothing else with that `ctx`.

use crate::diagnostics;
use crate::diagnostics::DiagnosticSink;
use crate::diagnostics::ExecuteContext;
use crate::diagnostics::LiveSink;
use crate::engine_ffi;
use crate::engine_ffi::FuzzTestAdapter;
use crate::engine_ffi::FuzzTestAdapterCtx;
use crate::engine_ffi::FuzzTestAdapterManager;
use crate::engine_ffi::FuzzTestAdapterManagerCtx;
use crate::engine_ffi::FuzzTestBytesSink;
use crate::engine_ffi::FuzzTestBytesView;
use crate::engine_ffi::FuzzTestBytesViews;
use crate::engine_ffi::FuzzTestCoverageDomainRegistry;
use crate::engine_ffi::FuzzTestDiagnosticSink;
use crate::engine_ffi::FuzzTestFeedbackSink;
use crate::engine_ffi::FuzzTestInputHandle;
use crate::engine_ffi::FuzzTestInputSink;
use crate::Adapter;
use crate::AdapterManager;
use safer_cffi::Handle;
use safer_cffi::OpaqueTracker;
use safer_cffi::Tracker;
use std::ffi::c_int;
use std::mem::MaybeUninit;
use std::ptr;

/// What the `ctx` of a `FuzzTestAdapter` points to.
struct AdapterState<A: Adapter> {
    adapter: A,
    /// The inputs that the adapter emitted and that the engine has not freed yet.
    ///
    /// The tracker lends an input to one borrower at a time. Each callback borrows at most one
    /// input, and rules 1 and 2 imply that no other callback runs meanwhile; if the engine
    /// broke them, the tracker would return an error.
    ///
    /// A callback that takes two handles must compare them before it borrows both: the engine
    /// may pass the same input twice, as `engine_abi.h` allows for the `origin` and `other` of
    /// `CrossOver`, and a second borrow of the same input fails.
    inputs: OpaqueTracker<A::Input>,
    // Safety invariant: a copy of the diagnostic sink that `construct_adapter` received when
    // it created this state.
    diagnostics: DiagnosticSink,
}

/// Converts a handle that crosses the ABI as an integer into a handle of the tracker.
fn tracker_handle<T>(handle: FuzzTestInputHandle) -> Handle<T> {
    // `Handle` converts from a pointer only. This one is the integer in another type: it has no
    // provenance and nothing dereferences it.
    Handle::from(ptr::without_provenance_mut::<T>(handle.0))
}

/// Converts a handle of the tracker into the integer that crosses the ABI.
fn abi_handle<T>(handle: Handle<T>) -> FuzzTestInputHandle {
    FuzzTestInputHandle(handle.into_opaque_ptr().addr())
}

impl<A: Adapter> AdapterState<A> {
    /// Runs `f` with the live adapter that `ctx` points to. Does nothing if `ctx` is null.
    ///
    /// This function picks the lifetime of what it lends to `f`, so `f` cannot keep any of it
    /// after it returns.
    ///
    /// # Safety
    ///
    /// `ctx` must be null, or the `ctx` that `construct_adapter` stored in a `FuzzTestAdapter`
    /// for an adapter of type `A`. `free_ctx` must not have been called with it, and must not be
    /// called with it before this function returns. The caller must be on the thread that ran
    /// `construct_adapter`: the state need not be `Send` or `Sync`.
    unsafe fn with_live(ctx: *mut FuzzTestAdapterCtx, f: impl FnOnce(&Live<'_, A>)) {
        // SAFETY: by this function's contract, a `ctx` that is not null comes from the
        // `Box<Self>` that `construct_adapter` leaked, so it is aligned and it points to an
        // initialized `Self`. Only `free_ctx` accesses that value other than through a shared
        // reference, and it does not run before this function returns. The value stays on the
        // thread that created it.
        let Some(state) = (unsafe { ctx.cast::<Self>().as_ref() }) else {
            return;
        };
        // SAFETY: by the invariant of the field, `state.diagnostics` is a copy of the sink that
        // `construct_adapter` received for this adapter, and the caller of `construct_adapter`
        // keeps that sink usable on this thread until `free_ctx` is called for the adapter. By
        // this function's contract that does not happen before `f` returns, and the witness
        // does not outlive `f`.
        let errors = unsafe { state.diagnostics.assume_live() };
        f(&Live {
            adapter: &state.adapter,
            inputs: &state.inputs,
            diagnostics: &state.diagnostics,
            errors,
        });
    }
}

/// A live adapter, as one of its callbacks sees it: the engine has not freed it, and does not
/// free it while this value exists. Only `AdapterState::with_live` creates one.
struct Live<'call, A: Adapter> {
    adapter: &'call A,
    /// The inputs of the adapter, see `AdapterState::inputs`.
    inputs: &'call OpaqueTracker<A::Input>,
    /// The diagnostic sink of the adapter, for `diagnostics::execute_scope`.
    diagnostics: &'call DiagnosticSink,
    /// The witness that errors can be reported to that sink.
    errors: LiveSink<'call>,
}

impl<A: Adapter> Live<'_, A> {
    /// Reports an unrecoverable error of the adapter to the engine.
    fn emit_error(&self, message: &str) {
        self.errors.emit_error(message);
    }

    /// Runs `f` with the input that `handle` refers to.
    ///
    /// Reports an error to the engine and returns `None` if `handle` refers to no input.
    fn with_input<R>(
        &self,
        callback: &str,
        handle: FuzzTestInputHandle,
        f: impl FnOnce(&A::Input) -> R,
    ) -> Option<R> {
        match self.inputs.borrow_mut(tracker_handle::<A::Input>(handle)) {
            // The tracker gets the input back when `input` is dropped, after `f` returns.
            Ok(input) => Some(f(&input)),
            Err(e) => {
                self.emit_error(&format!("{callback}: invalid input handle: {e}"));
                None
            }
        }
    }

    /// Hands `input` over to the engine through `sink`, or reports why the adapter has none.
    fn emit_input(
        &self,
        failure: &str,
        input: Result<A::Input, A::Error>,
        sink: &FuzzTestInputSink,
    ) {
        let input = match input {
            Ok(input) => input,
            Err(e) => {
                self.emit_error(&format!("{failure}: {e:?}"));
                return;
            }
        };
        match self.inputs.register(Box::new(input)) {
            Ok(handle) => sink.emit(abi_handle(handle)),
            // The tracker is full.
            Err(e) => self.emit_error(&format!("{failure}: {e}")),
        }
    }
}

/// Runs `f` with the manager that `ctx` points to. Does nothing if `ctx` is null.
///
/// This function picks the lifetime of the reference that it lends to `f`, so `f` cannot keep
/// the reference after it returns.
///
/// # Safety
///
/// `ctx` must be null, or the `ctx` of a table that `manager_table::<M>` built from a manager
/// that stays borrowed until this function returns. The caller must be on the thread that
/// holds that borrow: `M` need not be `Sync`.
unsafe fn with_manager<M: AdapterManager>(ctx: *mut FuzzTestAdapterManagerCtx, f: impl FnOnce(&M)) {
    // SAFETY: by this function's contract, a `ctx` that is not null was derived from a `&M`
    // whose borrow lasts until this function returns. It is therefore aligned, it points to an
    // initialized `M`, and no exclusive reference to that `M` exists until then. The reference
    // stays on the thread that holds the borrow.
    if let Some(manager) = unsafe { ctx.cast::<M>().as_ref() } {
        f(manager);
    }
}

/// Builds the table of callbacks that forward to `manager`.
///
/// The table points to `manager`, so the engine must only use it while `manager` is borrowed.
///
/// # Safety-usable invariant
///
/// The returned table's `ctx` is derived from `manager: &M`, and only `manager_table::<M>`
/// installs `get_binary_id::<M>`, `get_test_name::<M>`, and `construct_adapter::<M>`.
fn manager_table<M: AdapterManager>(manager: &M) -> FuzzTestAdapterManager {
    FuzzTestAdapterManager {
        // Only ever read through, by `with_manager`.
        ctx: ptr::from_ref(manager).cast_mut().cast(),
        get_binary_id: Some(get_binary_id::<M>),
        get_test_name: Some(get_test_name::<M>),
        construct_adapter: Some(construct_adapter::<M>),
    }
}

/// `FuzzTestAdapterManager::GetBinaryId`.
///
/// # Safety
///
/// See the [engine contract](self#engine-contract).
unsafe extern "C" fn get_binary_id<M: AdapterManager>(
    ctx: *mut FuzzTestAdapterManagerCtx,
    sink: Option<&FuzzTestBytesSink>,
) {
    let Some(sink) = sink else {
        return;
    };
    let body = |manager: &M| sink.emit(&manager.binary_id());
    // SAFETY: only `manager_table::<M>` installs this function, so by rule 3 `ctx` is the one
    // that it stored. By rule 1 the engine calls this function on the thread that gave it the
    // table, before `run_worker_if_requested` or `run_controller` returns, and both keep the
    // manager borrowed until then.
    unsafe { with_manager::<M>(ctx, body) };
}

/// `FuzzTestAdapterManager::GetTestName`.
///
/// # Safety
///
/// See the [engine contract](self#engine-contract).
unsafe extern "C" fn get_test_name<M: AdapterManager>(
    ctx: *mut FuzzTestAdapterManagerCtx,
    sink: Option<&FuzzTestBytesSink>,
) {
    let Some(sink) = sink else {
        return;
    };
    let body = |manager: &M| sink.emit(manager.test_name().as_bytes());
    // SAFETY: see `get_binary_id`.
    unsafe { with_manager::<M>(ctx, body) };
}

/// `FuzzTestAdapterManager::ConstructAdapter`.
///
/// # Safety-usable invariant
///
/// When this function writes to `adapter_out`, `ctx` is
/// `Box::into_raw(Box<AdapterState<M::Adapter>>)` created on the current thread with a retained
/// copy of `diagnostic_sink`, and only `construct_adapter` installs the adapter callbacks for `A =
/// M::Adapter`.
///
/// # Safety
///
/// See the [engine contract](self#engine-contract). In addition, `diagnostic_sink` must stay
/// usable until this function returns and, if it constructs an adapter, until `free_ctx` is
/// called with the `ctx` of that adapter: its `emit_error` function is null, or it may be
/// called on this thread with the `ctx` of the sink and a view that is valid for the call.
/// `engine_abi.h` says that the engine keeps the sink alive until then.
unsafe extern "C" fn construct_adapter<M: AdapterManager>(
    ctx: *mut FuzzTestAdapterManagerCtx,
    diagnostic_sink: Option<&FuzzTestDiagnosticSink>,
    adapter_out: Option<&mut MaybeUninit<FuzzTestAdapter>>,
) {
    let (Some(diagnostic_sink), Some(adapter_out)) = (diagnostic_sink, adapter_out) else {
        return;
    };
    let body = |manager: &M| {
        // The copy is inert: the callback that calls the sink through it vouches for the sink at
        // that moment.
        let diagnostics = DiagnosticSink::retain(diagnostic_sink);
        // The adapter is claimed before the manager constructs it, so that a second adapter is
        // refused without running any code of the manager. If the manager panics, the process
        // aborts at this `extern "C"` boundary, so no claim is left without an adapter.
        if !diagnostics::claim_adapter() {
            // SAFETY: by the contract of `construct_adapter`, `diagnostic_sink` is usable on this
            // thread until it returns, and the witness is dropped at the end of this statement.
            unsafe { diagnostics.assume_live() }
                .emit_error("ConstructAdapter: another adapter is still alive in this process");
            return;
        }
        // `diagnostics` is the copy of the sink of this call, as the invariant of the field
        // requires.
        let state = Box::new(AdapterState {
            adapter: manager.construct_adapter(),
            inputs: OpaqueTracker::new(),
            diagnostics,
        });
        adapter_out.write(FuzzTestAdapter {
            // The engine owns the state from here on, and `free_ctx` takes it back.
            ctx: Box::into_raw(state).cast(),
            set_up_coverage_domains: Some(set_up_coverage_domains::<M::Adapter>),
            // The optional callbacks that `Adapter` has no method for stay null. The engine then
            // uses its own fallback: no preset seeds, `Mutate` instead of `CrossOver`, and no input
            // metadata.
            get_preset_seed_inputs: None,
            get_random_seed_input: Some(get_random_seed_input::<M::Adapter>),
            mutate: Some(mutate::<M::Adapter>),
            cross_over: None,
            execute: Some(execute::<M::Adapter>),
            serialize_input_content: Some(serialize_input_content::<M::Adapter>),
            deserialize_input_content: Some(deserialize_input_content::<M::Adapter>),
            serialize_input_metadata: None,
            update_input_metadata: None,
            free_input: Some(free_input::<M::Adapter>),
            free_ctx: Some(free_ctx::<M::Adapter>),
        });
    };
    // SAFETY: see `get_binary_id`.
    unsafe { with_manager::<M>(ctx, body) };
}

/// `FuzzTestAdapter::SetUpCoverageDomains`.
///
/// # Safety
///
/// See the [engine contract](self#engine-contract).
unsafe extern "C" fn set_up_coverage_domains<A: Adapter>(
    ctx: *mut FuzzTestAdapterCtx,
    registry: Option<&FuzzTestCoverageDomainRegistry>,
) {
    let Some(registry) = registry else {
        return;
    };
    let body = |state: &Live<'_, A>| state.adapter.set_up_coverage_domains(registry);
    // SAFETY: only `construct_adapter` installs this function, for the adapter type `A` of the
    // state that it stores as `ctx`. By rule 3 this is that `ctx`, and the engine has not
    // called `free_ctx` with it. By rule 1 it does not call `free_ctx` before this function
    // returns, and this is the thread that ran `construct_adapter`.
    unsafe { AdapterState::<A>::with_live(ctx, body) };
}

/// `FuzzTestAdapter::GetRandomSeedInput`.
///
/// # Safety
///
/// See the [engine contract](self#engine-contract).
unsafe extern "C" fn get_random_seed_input<A: Adapter>(
    ctx: *mut FuzzTestAdapterCtx,
    sink: Option<&FuzzTestInputSink>,
) {
    let Some(sink) = sink else {
        return;
    };
    let body = |state: &Live<'_, A>| {
        let input = state.adapter.random_seed_input();
        state.emit_input("Failed to initialize random seed", input, sink);
    };
    // SAFETY: see `set_up_coverage_domains`.
    unsafe { AdapterState::<A>::with_live(ctx, body) };
}

/// `FuzzTestAdapter::Mutate`.
///
/// # Safety
///
/// See the [engine contract](self#engine-contract).
unsafe extern "C" fn mutate<A: Adapter>(
    ctx: *mut FuzzTestAdapterCtx,
    origin: FuzzTestInputHandle,
    shrink: c_int,
    sink: Option<&FuzzTestInputSink>,
) {
    let Some(sink) = sink else {
        return;
    };
    let body = |state: &Live<'_, A>| {
        let mutant =
            state.with_input("Mutate", origin, |origin| state.adapter.mutate(origin, shrink != 0));
        let Some(mutant) = mutant else {
            return;
        };
        state.emit_input("Failed to mutate", mutant, sink);
    };
    // SAFETY: see `set_up_coverage_domains`.
    unsafe { AdapterState::<A>::with_live(ctx, body) };
}

/// `FuzzTestAdapter::Execute`.
///
/// # Safety
///
/// See the [engine contract](self#engine-contract). In addition, the diagnostic sink that
/// `construct_adapter` received for this adapter must accept findings, as
/// [`diagnostics::execute_scope`] defines it, until this function returns. The engine accepts
/// findings for as long as it runs the `Execute` callback.
unsafe extern "C" fn execute<A: Adapter>(
    ctx: *mut FuzzTestAdapterCtx,
    input: FuzzTestInputHandle,
    sink: Option<&FuzzTestFeedbackSink>,
) {
    let Some(sink) = sink else {
        return;
    };
    let body = |state: &Live<'_, A>| {
        // The input stays borrowed from the tracker while the adapter executes it and emits
        // feedback. By rule 2 the sinks do not call back, so nothing asks for it meanwhile.
        state.with_input("Execute", input, |input| {
            let run = |cx: &ExecuteContext<'_>| state.adapter.execute(cx, input, sink);
            // SAFETY: by the invariant of the field, `state.diagnostics` is a copy of the
            // diagnostic sink that `construct_adapter` received for this adapter. By the
            // contract of `execute` that sink accepts findings until `execute` returns.
            unsafe { diagnostics::execute_scope(state.diagnostics, run) };
        });
    };
    // SAFETY: see `set_up_coverage_domains`.
    unsafe { AdapterState::<A>::with_live(ctx, body) };
}

/// `FuzzTestAdapter::SerializeInputContent`.
///
/// # Safety
///
/// See the [engine contract](self#engine-contract).
unsafe extern "C" fn serialize_input_content<A: Adapter>(
    ctx: *mut FuzzTestAdapterCtx,
    input: FuzzTestInputHandle,
    sink: Option<&FuzzTestBytesSink>,
) {
    let Some(sink) = sink else {
        return;
    };
    let body = |state: &Live<'_, A>| {
        let content = state.with_input("SerializeInputContent", input, |input| {
            state.adapter.serialize_input(input)
        });
        match content {
            Some(Ok(content)) => sink.emit(&content),
            Some(Err(e)) => state.emit_error(&format!("Failed to serialize input: {e:?}")),
            // `with_input` reported the handle.
            None => {}
        }
    };
    // SAFETY: see `set_up_coverage_domains`.
    unsafe { AdapterState::<A>::with_live(ctx, body) };
}

/// `FuzzTestAdapter::DeserializeInputContent`.
///
/// # Safety
///
/// See the [engine contract](self#engine-contract).
unsafe extern "C" fn deserialize_input_content<A: Adapter>(
    ctx: *mut FuzzTestAdapterCtx,
    content: Option<&FuzzTestBytesView<'_>>,
    sink: Option<&FuzzTestInputSink>,
) {
    let (Some(content), Some(sink)) = (content, sink) else {
        return;
    };
    let body = |state: &Live<'_, A>| {
        let input = state.adapter.deserialize_input(content.as_bytes());
        state.emit_input("Failed to deserialize input", input, sink);
    };
    // SAFETY: see `set_up_coverage_domains`.
    unsafe { AdapterState::<A>::with_live(ctx, body) };
}

/// `FuzzTestAdapter::FreeInput`.
///
/// # Safety
///
/// See the [engine contract](self#engine-contract).
unsafe extern "C" fn free_input<A: Adapter>(
    ctx: *mut FuzzTestAdapterCtx,
    input: FuzzTestInputHandle,
) {
    let body = |state: &Live<'_, A>| {
        match state.inputs.reclaim(tracker_handle::<A::Input>(input)) {
            // Dropped here, outside of the tracker: the destructor of an input is code of the
            // adapter.
            Ok(freed) => drop(freed),
            Err(e) => state.emit_error(&format!("FreeInput: invalid input handle: {e}")),
        }
    };
    // SAFETY: see `set_up_coverage_domains`.
    unsafe { AdapterState::<A>::with_live(ctx, body) };
}

/// `FuzzTestAdapter::FreeCtx`.
///
/// # Safety
///
/// See the [engine contract](self#engine-contract).
unsafe extern "C" fn free_ctx<A: Adapter>(ctx: *mut FuzzTestAdapterCtx) {
    // A null `ctx` belongs to no adapter, and the claim of a live adapter stays.
    if ctx.is_null() {
        return;
    }
    struct ReleaseOnDrop;
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            diagnostics::release_adapter();
        }
    }
    let _release = ReleaseOnDrop;
    // SAFETY: only `construct_adapter` installs this function, for the adapter type `A` of the
    // `Box<AdapterState<A>>` that it leaked as `ctx`. By rule 3 this is that `ctx`, and the
    // engine calls nothing else with it, so the box is taken back once. By rule 1 no other
    // callback of the adapter is running, so `AdapterState::with_live` is not lending the
    // state, and this is the thread that ran `construct_adapter`.
    let state = unsafe { Box::from_raw(ctx.cast::<AdapterState<A>>()) };
    drop(state);
}

/// How a run of the engine ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum RunOutcome {
    /// The test should finish with a success.
    Success,
    /// The test should finish with a failure.
    Failure,
}

/// Runs the test of `manager` as a FuzzTest worker, if the engine started this process as one.
///
/// Returns `None` if it did not: the caller decides what to run instead. Otherwise the engine
/// drives the test through `manager` on this thread, and this function returns when the engine
/// is done with it.
#[must_use]
pub fn run_worker_if_requested<M: AdapterManager>(manager: &M) -> Option<RunOutcome> {
    let table = manager_table(manager);
    // SAFETY:
    // - `table` is a manager table whose `ctx` points to `manager`. The engine only uses both
    //   during this call (`engine_worker_abi.h`), while `manager` is borrowed, and it calls the
    //   callbacks of `table` and of any constructed adapter on this thread according to the engine
    //   contract (`engine_abi.h`), so `M` and `M::Adapter` need not be `Send` or `Sync`.
    // - `construct_adapter`: the `diagnostic_sink` passed by the engine remains usable on this
    //   thread (its `emit_error` is null or callable with its `ctx` and a valid view) until
    //   `construct_adapter` returns and, if an adapter is constructed, until `free_ctx` is called.
    // - `execute`: the retained `diagnostic_sink` accepts findings (`emit_finding` is null or
    //   callable concurrently from any thread and async-signal-safely with its `ctx` and valid
    //   views) for the duration of each `Execute` call (`engine_abi.h`).
    // - Other threads may be inside the engine with the manager of another test, as when a test
    //   harness runs tests in parallel: the engine returns early for a test whose name is not the
    //   one it was started for, and `construct_adapter` refuses a second adapter while one is
    //   alive.
    let status = unsafe { engine_ffi::FuzzTestWorkerMaybeRun(&table) };
    match status {
        engine_ffi::WORKER_NOT_REQUIRED => None,
        engine_ffi::WORKER_SUCCESS => Some(RunOutcome::Success),
        engine_ffi::WORKER_FAILURE => Some(RunOutcome::Failure),
        unknown => {
            eprintln!("FuzzTest worker returned the unknown status {unknown}, taken as a failure");
            Some(RunOutcome::Failure)
        }
    }
}

/// Runs the FuzzTest controller with the command-line arguments `args`.
///
/// The controller runs the test of `manager` in worker processes that it starts.
pub fn run_controller<M: AdapterManager>(manager: &M, args: &[&[u8]]) -> RunOutcome {
    let table = manager_table(manager);
    let views: Vec<_> = args.iter().copied().map(FuzzTestBytesView::from_bytes).collect();
    let flags = FuzzTestBytesViews::from_slice(&views);
    // SAFETY:
    // - `table` is a manager table whose `ctx` points to `manager`, and `flags` upholds the
    //   `FuzzTestBytesViews` safety invariant because `views` borrows `args` for this call. The
    //   engine only uses `table`, `manager`, and `flags` during this call
    //   (`engine_controller_abi.h`), while all of them are borrowed.
    // - If the engine calls any manager or adapter callbacks, it does so on this thread according
    //   to the engine contract (`engine_abi.h`), keeping `diagnostic_sink` usable until `free_ctx`
    //   for `construct_adapter` and accepting findings concurrently/signal-safely during each
    //   `Execute` call.
    let status = unsafe { engine_ffi::FuzzTestControllerRun(&table, &flags) };
    if status == engine_ffi::CONTROLLER_SUCCESS {
        RunOutcome::Success
    } else {
        RunOutcome::Failure
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::ExecuteContext;
    use crate::diagnostics::TEST_TURN;
    use crate::engine_ffi::CoverageDomain;
    use crate::engine_ffi::FuzzTestBytesSinkCtx;
    use crate::engine_ffi::FuzzTestCoverageDomain;
    use crate::engine_ffi::FuzzTestDiagnosticSinkCtx;
    use crate::engine_ffi::FuzzTestDomainRegistryCtx;
    use crate::engine_ffi::FuzzTestFeedbackSinkCtx;
    use crate::engine_ffi::FuzzTestInputSinkCtx;
    use crate::engine_ffi::FuzzTestUint64sView;
    use googletest::prelude::*;
    use std::cell::{Cell, RefCell};
    use std::sync::MutexGuard;

    struct TestManager;

    impl AdapterManager for TestManager {
        type Adapter = TestAdapter;

        fn binary_id(&self) -> Vec<u8> {
            b"test-binary".to_vec()
        }

        fn test_name(&self) -> String {
            "suite.test".to_string()
        }

        fn construct_adapter(&self) -> TestAdapter {
            TestAdapter
        }
    }

    /// An adapter whose inputs are byte strings, and whose behavior depends on their content.
    struct TestAdapter;

    impl Adapter for TestAdapter {
        type Input = Vec<u8>;
        type Error = &'static str;

        fn set_up_coverage_domains(&self, registry: &FuzzTestCoverageDomainRegistry) {
            // The largest values that a registry accepts.
            registry.register(CoverageDomain {
                domain_id: 31,
                name: "test domain",
                feature_id_bit_size: 27,
                counter_bit_size: 32,
            });
        }

        fn random_seed_input(&self) -> Result<Self::Input, Self::Error> {
            if FAIL_RANDOM_SEED.get() {
                return Err("Intentional seed failure");
            }
            Ok(b"seed".to_vec())
        }

        fn mutate(&self, origin: &Self::Input, shrink: bool) -> Result<Self::Input, Self::Error> {
            if origin == b"immutable" {
                return Err("Intentional mutate failure");
            }
            let mut mutant = origin.clone();
            if shrink {
                mutant.pop();
            } else {
                mutant.push(b'!');
            }
            Ok(mutant)
        }

        fn execute(
            &self,
            cx: &ExecuteContext<'_>,
            input: &Self::Input,
            feedback: &FuzzTestFeedbackSink,
        ) {
            let features: &[u64] = match input.as_slice() {
                b"fail" => {
                    cx.emit_finding("the test failed", "failure signature");
                    &[7, 9]
                }
                // What a crash hook does. The feature tells the test whether the finding was
                // accepted.
                b"crash" => {
                    if diagnostics::try_emit_finding("the test crashed", "crash signature") {
                        &[1]
                    } else {
                        &[0]
                    }
                }
                _ => &[7, 9],
            };
            feedback.emit_coverage_features(features);
        }

        fn serialize_input(&self, input: &Self::Input) -> Result<Vec<u8>, Self::Error> {
            if input == b"unserializable" {
                return Err("Intentional serialize failure");
            }
            Ok(input.clone())
        }

        fn deserialize_input(&self, content: &[u8]) -> Result<Self::Input, Self::Error> {
            if content == b"corrupt" {
                return Err("Intentional deserialize failure");
            }
            Ok(content.to_vec())
        }
    }

    /// A coverage domain that the registry of the fake engine received.
    #[derive(Debug, PartialEq, Eq)]
    struct RegisteredDomain {
        domain_id: u8,
        name: String,
        feature_id_bit_size: u8,
        counter_bit_size: u8,
    }

    /// What the sinks and the registry of the fake engine received.
    #[derive(Debug, Default, PartialEq, Eq)]
    struct Received {
        errors: Vec<String>,
        findings: Vec<(String, String)>,
        inputs: Vec<FuzzTestInputHandle>,
        bytes: Vec<u8>,
        features: Vec<u64>,
        domains: Vec<RegisteredDomain>,
    }

    fn received_bytes(bytes: &[u8]) -> Received {
        Received { bytes: bytes.to_vec(), ..Received::default() }
    }

    fn received_error(message: &str) -> Received {
        Received { errors: vec![message.to_string()], ..Received::default() }
    }

    /// Returns the only input in `received`, or fails the test.
    ///
    /// This does not panic: the caller holds the turn of the tests, and a panic would poison it
    /// for the tests that follow.
    fn only_input(received: &Received) -> Result<FuzzTestInputHandle> {
        verify_that!(received.inputs, len(eq(1)))?;
        Ok(received.inputs[0])
    }

    thread_local! {
        // The callbacks emit on the thread that called them, which is the thread of the test.
        static RECEIVED: RefCell<Received> = RefCell::new(Received::default());
        static FAIL_RANDOM_SEED: Cell<bool> = const { Cell::new(false) };
    }

    fn text(view: &FuzzTestBytesView<'_>) -> String {
        String::from_utf8_lossy(view.as_bytes()).into_owned()
    }

    extern "C" fn record_error(
        _ctx: *mut FuzzTestDiagnosticSinkCtx,
        message: &FuzzTestBytesView<'_>,
    ) {
        RECEIVED.with_borrow_mut(|received| received.errors.push(text(message)));
    }

    extern "C" fn record_finding(
        _ctx: *mut FuzzTestDiagnosticSinkCtx,
        description: &FuzzTestBytesView<'_>,
        signature: &FuzzTestBytesView<'_>,
    ) {
        RECEIVED.with_borrow_mut(|received| {
            received.findings.push((text(description), text(signature)));
        });
    }

    extern "C" fn record_input(_ctx: *mut FuzzTestInputSinkCtx, input: FuzzTestInputHandle) {
        RECEIVED.with_borrow_mut(|received| received.inputs.push(input));
    }

    extern "C" fn record_bytes(_ctx: *mut FuzzTestBytesSinkCtx, view: &FuzzTestBytesView<'_>) {
        RECEIVED.with_borrow_mut(|received| received.bytes.extend_from_slice(view.as_bytes()));
    }

    extern "C" fn record_features(
        _ctx: *mut FuzzTestFeedbackSinkCtx,
        features: &FuzzTestUint64sView<'_>,
    ) {
        RECEIVED.with_borrow_mut(|received| {
            received.features.extend_from_slice(features.as_slice());
        });
    }

    extern "C" fn record_domain(
        _ctx: *mut FuzzTestDomainRegistryCtx,
        domain: &FuzzTestCoverageDomain<'_>,
    ) {
        RECEIVED.with_borrow_mut(|received| {
            received.domains.push(RegisteredDomain {
                domain_id: domain.domain_id,
                name: text(&domain.name),
                feature_id_bit_size: domain.feature_id_bit_size,
                counter_bit_size: domain.counter_bit_size,
            });
        });
    }

    /// The diagnostic sink of the fake engine.
    ///
    /// # Safety-usable invariant
    ///
    /// Its callbacks are safe functions that ignore `ctx`, so it may be used at any time and
    /// from any thread, and it accepts findings at any time.
    fn diagnostic_sink() -> FuzzTestDiagnosticSink {
        FuzzTestDiagnosticSink {
            ctx: ptr::null_mut(),
            emit_error: Some(record_error),
            emit_warning: None,
            emit_finding: Some(record_finding),
        }
    }

    fn empty_adapter() -> FuzzTestAdapter {
        FuzzTestAdapter {
            ctx: ptr::null_mut(),
            set_up_coverage_domains: None,
            get_preset_seed_inputs: None,
            get_random_seed_input: None,
            mutate: None,
            cross_over: None,
            execute: None,
            serialize_input_content: None,
            deserialize_input_content: None,
            serialize_input_metadata: None,
            update_input_metadata: None,
            free_input: None,
            free_ctx: None,
        }
    }

    /// Asks `manager` for an adapter the way the engine does. Returns `None` if `manager`
    /// constructed none.
    fn construct_adapter_of(manager: &TestManager) -> Option<FuzzTestAdapter> {
        let table = manager_table(manager);
        let construct_adapter = table.construct_adapter.expect("installed by manager_table");
        let mut adapter = MaybeUninit::new(empty_adapter());
        // SAFETY: this follows the engine contract. `table.ctx` points to `manager`, which is
        // borrowed. The sink and `adapter` are valid for the call, and the sink stays usable
        // after it, see `diagnostic_sink`.
        unsafe { construct_adapter(table.ctx, Some(&diagnostic_sink()), Some(&mut adapter)) };
        // SAFETY: `adapter` was initialized by `MaybeUninit::new`, and `construct_adapter` only
        // ever writes a whole table to it.
        let adapter = unsafe { adapter.assume_init() };
        (!adapter.ctx.is_null()).then_some(adapter)
    }

    /// Plays the engine for one adapter of `TestManager`.
    ///
    /// Each method calls one callback of the adapter the way the engine contract requires: on
    /// the thread of the test, with arguments that are valid for the call, and with sinks and a
    /// registry that record what they receive in `RECEIVED` and call nothing back. It returns
    /// what they received. Like the engine, it frees every input that it received before it
    /// frees the adapter.
    struct FakeEngine {
        // Safety invariant: `construct_adapter::<TestManager>` filled this table in, and
        // `free_ctx` has not been called.
        adapter: FuzzTestAdapter,
        // Safety invariant: the handles that `adapter` emitted and that `free_input` has not
        // been called with.
        inputs: RefCell<Vec<FuzzTestInputHandle>>,
        // The diagnostics slot is process-wide, so the tests that have an adapter take turns.
        // Released after `drop` freed the adapter.
        _turn: MutexGuard<'static, ()>,
    }

    impl FakeEngine {
        fn start() -> Self {
            let turn = TEST_TURN.lock().expect("an earlier test panicked");
            RECEIVED.take();
            FAIL_RANDOM_SEED.set(false);
            let adapter = construct_adapter_of(&TestManager).expect("no other adapter is alive");
            Self { adapter, inputs: RefCell::new(Vec::new()), _turn: turn }
        }

        /// Returns what the sinks received since the last call, and keeps track of the inputs.
        fn received(&self) -> Received {
            let received = RECEIVED.take();
            self.inputs.borrow_mut().extend_from_slice(&received.inputs);
            received
        }

        fn set_up_coverage_domains(&self) -> Received {
            let callback = self.adapter.set_up_coverage_domains.expect("required callback");
            let registry = FuzzTestCoverageDomainRegistry::for_test(record_domain);
            // SAFETY: by the struct invariant and as described on `FakeEngine`.
            unsafe { callback(self.adapter.ctx, Some(&registry)) };
            self.received()
        }

        fn random_seed_input(&self) -> Received {
            let callback = self.adapter.get_random_seed_input.expect("required callback");
            let sink = FuzzTestInputSink::for_test(record_input);
            // SAFETY: by the struct invariant and as described on `FakeEngine`.
            unsafe { callback(self.adapter.ctx, Some(&sink)) };
            self.received()
        }

        fn mutate(&self, origin: FuzzTestInputHandle, shrink: bool) -> Received {
            let callback = self.adapter.mutate.expect("required callback");
            let sink = FuzzTestInputSink::for_test(record_input);
            // SAFETY: by the struct invariant and as described on `FakeEngine`.
            unsafe { callback(self.adapter.ctx, origin, c_int::from(shrink), Some(&sink)) };
            self.received()
        }

        fn execute(&self, input: FuzzTestInputHandle) -> Received {
            let callback = self.adapter.execute.expect("required callback");
            let sink = FuzzTestFeedbackSink::for_test(record_features);
            // SAFETY: by the struct invariant and as described on `FakeEngine`. The diagnostic
            // sink of the fake engine accepts findings at any time.
            unsafe { callback(self.adapter.ctx, input, Some(&sink)) };
            self.received()
        }

        fn serialize(&self, input: FuzzTestInputHandle) -> Received {
            let callback = self.adapter.serialize_input_content.expect("required callback");
            let sink = FuzzTestBytesSink::for_test(record_bytes);
            // SAFETY: by the struct invariant and as described on `FakeEngine`.
            unsafe { callback(self.adapter.ctx, input, Some(&sink)) };
            self.received()
        }

        fn deserialize(&self, content: &[u8]) -> Received {
            let callback = self.adapter.deserialize_input_content.expect("required callback");
            let content = FuzzTestBytesView::from_bytes(content);
            let sink = FuzzTestInputSink::for_test(record_input);
            // SAFETY: by the struct invariant and as described on `FakeEngine`.
            unsafe { callback(self.adapter.ctx, Some(&content), Some(&sink)) };
            self.received()
        }

        fn free_input(&self, input: FuzzTestInputHandle) -> Received {
            let callback = self.adapter.free_input.expect("required callback");
            self.inputs.borrow_mut().retain(|live| *live != input);
            // SAFETY: by the struct invariants and as described on `FakeEngine`.
            unsafe { callback(self.adapter.ctx, input) };
            self.received()
        }
    }

    impl Drop for FakeEngine {
        fn drop(&mut self) {
            let free_input = self.adapter.free_input.expect("required callback");
            for input in self.inputs.take() {
                // SAFETY: by the struct invariants and as described on `FakeEngine`. This is
                // the only `FreeInput` call with `input`.
                unsafe { free_input(self.adapter.ctx, input) };
            }
            let free_ctx = self.adapter.free_ctx.expect("required callback");
            // SAFETY: by the struct invariants and as described on `FakeEngine`. This is the
            // last call with this `ctx`.
            unsafe { free_ctx(self.adapter.ctx) };
        }
    }

    #[gtest]
    fn only_the_required_callbacks_are_installed() {
        let engine = FakeEngine::start();
        let adapter = &engine.adapter;

        expect_false!(adapter.ctx.is_null());
        expect_true!(adapter.set_up_coverage_domains.is_some());
        expect_true!(adapter.get_random_seed_input.is_some());
        expect_true!(adapter.mutate.is_some());
        expect_true!(adapter.execute.is_some());
        expect_true!(adapter.serialize_input_content.is_some());
        expect_true!(adapter.deserialize_input_content.is_some());
        expect_true!(adapter.free_input.is_some());
        expect_true!(adapter.free_ctx.is_some());
        // The engine has a fallback for these.
        expect_true!(adapter.get_preset_seed_inputs.is_none());
        expect_true!(adapter.cross_over.is_none());
        expect_true!(adapter.serialize_input_metadata.is_none());
        expect_true!(adapter.update_input_metadata.is_none());
    }

    #[gtest]
    fn the_coverage_domains_of_the_adapter_reach_the_registry() {
        let engine = FakeEngine::start();

        expect_eq!(
            engine.set_up_coverage_domains(),
            Received {
                domains: vec![RegisteredDomain {
                    domain_id: 31,
                    name: "test domain".to_string(),
                    feature_id_bit_size: 27,
                    counter_bit_size: 32,
                }],
                ..Received::default()
            }
        );
    }

    #[gtest]
    fn the_manager_callbacks_emit_the_test_name_and_the_binary_id() {
        let manager = TestManager;
        let table = manager_table(&manager);
        let get_test_name = table.get_test_name.expect("installed by manager_table");
        let get_binary_id = table.get_binary_id.expect("installed by manager_table");
        let sink = FuzzTestBytesSink::for_test(record_bytes);
        RECEIVED.take();

        // SAFETY: this follows the engine contract. `table.ctx` points to `manager`, which is
        // borrowed, and `sink` is valid for the call.
        unsafe { get_test_name(table.ctx, Some(&sink)) };
        let test_name = RECEIVED.take();
        // SAFETY: as above.
        unsafe { get_binary_id(table.ctx, Some(&sink)) };
        let binary_id = RECEIVED.take();

        expect_eq!(test_name, received_bytes(b"suite.test"));
        expect_eq!(binary_id, received_bytes(b"test-binary"));
    }

    #[gtest]
    fn inputs_are_passed_back_by_handle() -> Result<()> {
        let engine = FakeEngine::start();

        let seed = only_input(&engine.random_seed_input())?;
        let grown = only_input(&engine.mutate(seed, false))?;
        let shrunk = only_input(&engine.mutate(seed, true))?;

        expect_eq!(engine.serialize(seed), received_bytes(b"seed"));
        expect_eq!(engine.serialize(grown), received_bytes(b"seed!"));
        expect_eq!(engine.serialize(shrunk), received_bytes(b"see"));
        expect_eq!(engine.free_input(seed), Received::default());
        expect_eq!(engine.serialize(grown), received_bytes(b"seed!"));
        Ok(())
    }

    #[gtest]
    fn deserialized_content_becomes_an_input() -> Result<()> {
        let engine = FakeEngine::start();

        let input = only_input(&engine.deserialize(b"content"))?;

        expect_eq!(engine.serialize(input), received_bytes(b"content"));
        Ok(())
    }

    #[gtest]
    fn the_errors_of_the_adapter_are_reported_in_their_debug_format() -> Result<()> {
        let engine = FakeEngine::start();
        let immutable = only_input(&engine.deserialize(b"immutable"))?;
        let unserializable = only_input(&engine.deserialize(b"unserializable"))?;

        expect_eq!(
            engine.mutate(immutable, false),
            received_error("Failed to mutate: \"Intentional mutate failure\"")
        );
        expect_eq!(
            engine.serialize(unserializable),
            received_error("Failed to serialize input: \"Intentional serialize failure\"")
        );
        expect_eq!(
            engine.deserialize(b"corrupt"),
            received_error("Failed to deserialize input: \"Intentional deserialize failure\"")
        );
        Ok(())
    }

    fn expect_invalid_handle_error(received: Received, callback: &str) {
        expect_that!(received.errors, len(eq(1)));
        if let Some(error) = received.errors.first() {
            expect_true!(
                error.starts_with(&format!("{callback}: invalid input handle:")),
                "unexpected error message: {error}"
            );
        }
        expect_eq!(Received { errors: Vec::new(), ..received }, Received::default());
    }

    #[gtest]
    fn random_seed_input_error_is_reported() {
        let engine = FakeEngine::start();
        FAIL_RANDOM_SEED.set(true);
        let result = engine.random_seed_input();
        FAIL_RANDOM_SEED.set(false);

        expect_eq!(
            result,
            received_error("Failed to initialize random seed: \"Intentional seed failure\"")
        );
    }

    #[gtest]
    fn a_freed_input_is_reported_instead_of_used() -> Result<()> {
        let engine = FakeEngine::start();
        let input = only_input(&engine.random_seed_input())?;

        expect_eq!(engine.free_input(input), Received::default());

        expect_invalid_handle_error(engine.mutate(input, false), "Mutate");
        expect_invalid_handle_error(engine.execute(input), "Execute");
        expect_invalid_handle_error(engine.serialize(input), "SerializeInputContent");
        expect_invalid_handle_error(engine.free_input(input), "FreeInput");
        Ok(())
    }

    #[gtest]
    fn a_handle_that_was_never_issued_is_reported_instead_of_used() -> Result<()> {
        let engine = FakeEngine::start();
        // An input is alive, so that the tracker is not empty.
        let _seed = only_input(&engine.random_seed_input())?;

        for made_up in [FuzzTestInputHandle(0), FuzzTestInputHandle(usize::MAX)] {
            expect_invalid_handle_error(engine.mutate(made_up, false), "Mutate");
            expect_invalid_handle_error(engine.execute(made_up), "Execute");
            expect_invalid_handle_error(engine.serialize(made_up), "SerializeInputContent");
            expect_invalid_handle_error(engine.free_input(made_up), "FreeInput");
        }
        Ok(())
    }

    #[gtest]
    fn execute_emits_the_feedback_and_the_findings() -> Result<()> {
        let engine = FakeEngine::start();
        let passing = only_input(&engine.deserialize(b"pass"))?;
        let failing = only_input(&engine.deserialize(b"fail"))?;

        expect_eq!(
            engine.execute(passing),
            Received { features: vec![7, 9], ..Received::default() }
        );
        expect_eq!(
            engine.execute(failing),
            Received {
                features: vec![7, 9],
                findings: vec![("the test failed".to_string(), "failure signature".to_string())],
                ..Received::default()
            }
        );
        Ok(())
    }

    #[gtest]
    fn a_crash_hook_reports_findings_during_execute_only() -> Result<()> {
        let engine = FakeEngine::start();
        let crashing = only_input(&engine.deserialize(b"crash"))?;

        expect_false!(diagnostics::try_emit_finding("early", "early signature"));
        let during_execute = engine.execute(crashing);
        expect_false!(diagnostics::try_emit_finding("late", "late signature"));

        expect_eq!(
            during_execute,
            Received {
                features: vec![1],
                findings: vec![("the test crashed".to_string(), "crash signature".to_string())],
                ..Received::default()
            }
        );
        expect_eq!(RECEIVED.take(), Received::default());
        Ok(())
    }

    #[gtest]
    fn a_second_adapter_is_refused_while_the_first_is_alive() -> Result<()> {
        let engine = FakeEngine::start();

        let second = construct_adapter_of(&TestManager);
        let received = RECEIVED.take();

        expect_true!(second.is_none());
        expect_eq!(
            received,
            received_error("ConstructAdapter: another adapter is still alive in this process")
        );
        // The first adapter is not affected.
        let seed = only_input(&engine.random_seed_input())?;
        expect_eq!(engine.serialize(seed), received_bytes(b"seed"));
        Ok(())
    }

    #[gtest]
    fn an_adapter_can_be_constructed_once_the_previous_one_is_freed() {
        drop(FakeEngine::start());

        let engine = FakeEngine::start();

        expect_eq!(engine.deserialize(b"corrupt").errors.len(), 1);
    }

    #[gtest]
    fn null_arguments_are_ignored() -> Result<()> {
        let engine = FakeEngine::start();
        let adapter = &engine.adapter;
        let input = only_input(&engine.random_seed_input())?;
        let get_random_seed_input = adapter.get_random_seed_input.expect("required callback");
        let serialize_input_content = adapter.serialize_input_content.expect("required callback");
        let deserialize_input_content =
            adapter.deserialize_input_content.expect("required callback");
        let sink = FuzzTestInputSink::for_test(record_input);

        // SAFETY: as described on `FakeEngine`, with a null `ctx`.
        unsafe { get_random_seed_input(ptr::null_mut(), Some(&sink)) };
        // SAFETY: as described on `FakeEngine`, with a null sink.
        unsafe { serialize_input_content(adapter.ctx, input, None) };
        // SAFETY: as described on `FakeEngine`, with a null view.
        unsafe { deserialize_input_content(adapter.ctx, None, Some(&sink)) };

        expect_eq!(RECEIVED.take(), Received::default());
        Ok(())
    }

    #[gtest]
    fn free_ctx_with_a_null_ctx_keeps_the_live_adapter() -> Result<()> {
        let engine = FakeEngine::start();
        let free_ctx = engine.adapter.free_ctx.expect("required callback");
        let crashing = only_input(&engine.deserialize(b"crash"))?;

        // SAFETY: as described on `FakeEngine`, with a null `ctx`.
        unsafe { free_ctx(ptr::null_mut()) };

        // A crash hook still reaches the diagnostic sink of the adapter.
        expect_eq!(
            engine.execute(crashing),
            Received {
                features: vec![1],
                findings: vec![("the test crashed".to_string(), "crash signature".to_string())],
                ..Received::default()
            }
        );
        Ok(())
    }

    #[gtest]
    fn the_worker_does_not_run_in_a_process_that_the_engine_did_not_start() {
        expect_true!(run_worker_if_requested(&TestManager).is_none());
    }
}
