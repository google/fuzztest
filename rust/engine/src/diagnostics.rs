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

//! The diagnostic sink of the engine, and the process-wide state that lets crash hooks use it.
//!
//! A sanitizer or signal hook has no adapter pointer, may run on any thread, and may run inside
//! a signal handler. The diagnostic sink of the adapter is therefore published here for as long
//! as the engine is inside `Execute`, which is the only time a finding may be emitted.

use crate::engine_ffi::FuzzTestBytesView;
use crate::engine_ffi::FuzzTestDiagnosticSink;
use crate::engine_ffi::FuzzTestDiagnosticSinkCtx;
use spin::Mutex as SpinMutex;
use std::marker::PhantomData;
#[cfg(test)]
use std::sync::Mutex;

/// A copy of the diagnostic sink of an adapter, which outlives the call that lent the sink.
///
/// Copies only the fields that this crate reads (`ctx`, `emit_error`, `emit_finding`), so
/// `retain` never reads `emit_warning`.
///
/// The copy is inert: holding it calls nothing. Every call through it is vouched for where it
/// is made, by [`DiagnosticSink::assume_live`] or by [`execute_scope`].
pub(crate) struct DiagnosticSink {
    ctx: *mut FuzzTestDiagnosticSinkCtx,
    emit_error: Option<
        unsafe extern "C" fn(ctx: *mut FuzzTestDiagnosticSinkCtx, message: &FuzzTestBytesView<'_>),
    >,
    emit_finding: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestDiagnosticSinkCtx,
            description: &FuzzTestBytesView<'_>,
            signature: &FuzzTestBytesView<'_>,
        ),
    >,
}

// SAFETY: the value is a context pointer and function pointers, and holding it calls nothing.
// The `unsafe` function that leads to a call states which threads may make it.
unsafe impl Send for DiagnosticSink {}
// SAFETY: as above.
unsafe impl Sync for DiagnosticSink {}

/// A witness that errors can be reported to a diagnostic sink.
///
/// [`DiagnosticSink::assume_live`] creates it, and its caller vouches for the sink for as long
/// as the witness exists.
pub(crate) struct LiveSink<'sink> {
    // Safety invariant: for as long as this value exists, the `emit_error` function of `sink`
    // is null, or it may be called with the `ctx` of `sink` and a view that is valid for the
    // call, from the thread that created this value. Only `assume_live` creates one.
    sink: &'sink DiagnosticSink,
    // The invariant is about one thread, so the witness stays on it.
    _not_send_nor_sync: PhantomData<*const ()>,
}

impl LiveSink<'_> {
    /// Reports an unrecoverable error to the engine.
    pub(crate) fn emit_error(&self, message: &str) {
        let emit = self.sink.emit_error.expect("EmitError is required by ABI");
        // SAFETY: by the struct invariant `emit`, which is not null, may be called with `ctx`
        // from this thread. The view borrows `message` for the duration of the call.
        unsafe { emit(self.sink.ctx, &FuzzTestBytesView::from_bytes(message.as_bytes())) }
    }
}

impl DiagnosticSink {
    /// Copies the fields used from `raw`, so that the copy can outlive the call that lent `raw`.
    pub(crate) fn retain(raw: &FuzzTestDiagnosticSink) -> Self {
        Self { ctx: raw.ctx, emit_error: raw.emit_error, emit_finding: raw.emit_finding }
    }

    /// Returns a witness that errors can be reported to this sink.
    ///
    /// # Safety
    ///
    /// For as long as the returned [`LiveSink`] exists, the `emit_error` function that this sink
    /// retained must be null, or a function that may be called from the current thread with the
    /// `ctx` of the same sink and a view that is valid for the call.
    pub(crate) unsafe fn assume_live(&self) -> LiveSink<'_> {
        LiveSink { sink: self, _not_send_nor_sync: PhantomData }
    }

    /// Reports a finding to the engine.
    ///
    /// # Safety
    ///
    /// This sink must accept findings, as [`execute_scope`] defines it, until this function
    /// returns.
    unsafe fn emit_finding_unchecked(&self, description: &str, signature: &str) {
        let emit = self.emit_finding.expect("EmitFinding is required by ABI");
        let description = FuzzTestBytesView::from_bytes(description.as_bytes());
        let signature = FuzzTestBytesView::from_bytes(signature.as_bytes());
        // SAFETY: by this function's contract `emit`, which is not null, may be called with
        // `ctx` from this thread. Both views borrow a `&str` for the duration of the call.
        unsafe { emit(self.ctx, &description, &signature) }
    }
}

/// A witness that the diagnostic sink of an adapter accepts findings, which the engine only
/// does while it is inside `Execute`.
///
/// [`Adapter::execute`](crate::Adapter::execute) borrows this value for the duration of the
/// call, and reports the findings of the execution through it.
pub struct ExecuteContext<'exec> {
    // Safety invariant: `sink` accepts findings, as `execute_scope` defines it, for as long as
    // this value exists. Only `execute_scope` creates one.
    sink: &'exec DiagnosticSink,
}

impl ExecuteContext<'_> {
    /// Reports a finding for the input that is being executed, with a human-readable
    /// `description` and a `signature` for deduplication.
    ///
    /// If several findings are reported for one execution, the engine keeps one of them.
    pub fn emit_finding(&self, description: &str, signature: &str) {
        // SAFETY: by the struct invariant `sink` accepts findings for as long as `self` is
        // borrowed.
        unsafe { self.sink.emit_finding_unchecked(description, signature) }
    }
}

/// What this module keeps for the whole process.
struct Process {
    // Whether an adapter is alive. No `unsafe` code relies on this field: it only makes
    // `claim_adapter` refuse a second adapter.
    adapter_alive: bool,
    // Safety invariant: `Some` only while the `execute_scope` call that stored the sink is
    // running. The caller of that call vouched that the sink accepts findings until the call
    // returns.
    executing: Option<DiagnosticSink>,
}

// A spin lock, because `try_emit_finding` may run inside a signal handler: it must not block,
// and it only ever uses `try_lock`. Everything else that takes the lock runs on the thread on
// which the engine calls the adapter.
//
// The lock is held across the call into the sink on purpose. The end of `execute_scope` takes
// it too, so the engine cannot leave `Execute` while another thread is in the middle of an
// emission.
static PROCESS: SpinMutex<Process> =
    SpinMutex::new(Process { adapter_alive: false, executing: None });

/// The state in this module is process-wide, so the tests that use it take turns.
#[cfg(test)]
pub(crate) static TEST_TURN: Mutex<()> = Mutex::new(());

/// Records that an adapter is about to be constructed.
///
/// Returns `false` and records nothing if another adapter is still alive. A crash hook could
/// not tell which of two live adapters a crash belongs to, so the caller must not construct a
/// second one.
#[must_use]
pub(crate) fn claim_adapter() -> bool {
    let mut process = PROCESS.lock();
    if process.adapter_alive {
        return false;
    }
    process.adapter_alive = true;
    true
}

/// Records that the engine freed the adapter that [`claim_adapter`] recorded.
pub(crate) fn release_adapter() {
    PROCESS.lock().adapter_alive = false;
}

/// Runs `f` with a witness that `sink` accepts findings, and lets [`try_emit_finding`] report
/// findings to `sink` for as long as `f` runs.
///
/// # Panics
///
/// Panics if another `execute_scope` call is already running.
///
/// # Safety
///
/// `sink` must *accept findings* until this function returns. A sink accepts findings when the
/// `emit_finding` function that it retained is null, or may be called with the `ctx` of
/// the same sink and two views that are valid for the call, from any thread and from several
/// threads at once. If the program calls [`try_emit_finding`] from a signal handler, that
/// function must be async-signal-safe too.
pub(crate) unsafe fn execute_scope<R>(
    sink: &DiagnosticSink,
    f: impl FnOnce(&ExecuteContext<'_>) -> R,
) -> R {
    /// Takes the published sink back.
    struct Withdraw;
    impl Drop for Withdraw {
        fn drop(&mut self) {
            // This waits for a crash hook that is in the middle of an emission.
            PROCESS.lock().executing = None;
        }
    }

    {
        let mut process = PROCESS.lock();
        assert!(process.executing.is_none(), "overlapping execute_scope calls are not supported");
        // By this function's contract `sink` accepts findings until `_withdraw` is dropped, which
        // is what the invariant of `executing` requires.
        process.executing = Some(DiagnosticSink {
            ctx: sink.ctx,
            emit_error: sink.emit_error,
            emit_finding: sink.emit_finding,
        });
        // The lock is released at the end of this block: `f` and the crash hooks take it again.
    }
    // Dropped when `f` returns or unwinds, before this function returns.
    let _withdraw = Withdraw;
    // By this function's contract `sink` accepts findings for as long as the witness exists.
    f(&ExecuteContext { sink })
}

/// Reports a finding from a crash hook, and returns whether it was emitted.
///
/// This function never blocks, so it can be called from a signal handler. It returns `false`
/// without emitting if the state is locked (for example because the crash interrupted this
/// thread inside this module), or if the engine is not inside `Execute`.
pub fn try_emit_finding(description: &str, signature: &str) -> bool {
    let Some(process) = PROCESS.try_lock() else {
        return false;
    };
    let Some(sink) = process.executing.as_ref() else {
        return false;
    };
    // SAFETY: by the invariant of `executing`, the `execute_scope` call that stored `sink` is
    // running, and its caller vouched that `sink` accepts findings until that call returns.
    // This thread holds the lock that the call takes before it returns, so `sink` keeps
    // accepting them until `emit_finding_unchecked` returns.
    unsafe { sink.emit_finding_unchecked(description, signature) };
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;
    use std::mem;
    use std::ptr;

    /// What the recording sink received.
    #[derive(Debug, PartialEq, Eq)]
    enum Emitted {
        Error(String),
        Finding { description: String, signature: String },
    }

    fn finding(description: &str, signature: &str) -> Emitted {
        Emitted::Finding { description: description.to_string(), signature: signature.to_string() }
    }

    // Not thread-local: a crash hook may emit from any thread.
    static EMITTED: Mutex<Vec<Emitted>> = Mutex::new(Vec::new());

    fn text(view: &FuzzTestBytesView<'_>) -> String {
        String::from_utf8_lossy(view.as_bytes()).into_owned()
    }

    extern "C" fn record_error(
        _ctx: *mut FuzzTestDiagnosticSinkCtx,
        message: &FuzzTestBytesView<'_>,
    ) {
        EMITTED.lock().expect("an earlier test panicked").push(Emitted::Error(text(message)));
    }

    extern "C" fn record_finding(
        _ctx: *mut FuzzTestDiagnosticSinkCtx,
        description: &FuzzTestBytesView<'_>,
        signature: &FuzzTestBytesView<'_>,
    ) {
        EMITTED
            .lock()
            .expect("an earlier test panicked")
            .push(finding(&text(description), &text(signature)));
    }

    /// Returns a sink that appends what it receives to `EMITTED`.
    ///
    /// # Safety-usable invariant
    ///
    /// Its callbacks are safe functions that ignore `ctx`, so the returned sink may be called at
    /// any time and from any thread, and it accepts findings at any time.
    fn recording_sink() -> DiagnosticSink {
        let sink = FuzzTestDiagnosticSink {
            ctx: ptr::null_mut(),
            emit_error: Some(record_error),
            emit_warning: None,
            emit_finding: Some(record_finding),
        };
        // The callbacks of `sink` are safe functions that ignore `ctx`, so they may be called
        // at any time and from any thread.
        DiagnosticSink::retain(&sink)
    }

    /// Runs `f` inside [`execute_scope`] with `sink`.
    fn in_execute_scope(sink: &DiagnosticSink, f: impl FnOnce(&ExecuteContext<'_>)) {
        // SAFETY: `sink` is a recording sink, which accepts findings at any time and from any
        // thread, see `recording_sink`. No test reports a finding from a signal handler.
        unsafe { execute_scope(sink, f) }
    }

    /// Runs `test` with no adapter claimed at the start, and returns what the recording sink
    /// received.
    fn emitted_by(test: impl FnOnce()) -> Vec<Emitted> {
        let _turn = TEST_TURN.lock().expect("an earlier test panicked");
        release_adapter();
        EMITTED.lock().expect("an earlier test panicked").clear();

        test();

        release_adapter();
        mem::take(&mut *EMITTED.lock().expect("an earlier test panicked"))
    }

    #[gtest]
    fn try_emit_finding_is_refused_outside_execute() {
        let emitted = emitted_by(|| {
            expect_true!(claim_adapter());

            expect_false!(try_emit_finding("description", "signature"));
        });

        expect_that!(emitted, is_empty());
    }

    #[gtest]
    fn findings_are_emitted_inside_execute_only() {
        let emitted = emitted_by(|| {
            let sink = recording_sink();

            in_execute_scope(&sink, |cx| {
                expect_true!(try_emit_finding("crash", "crash signature"));
                cx.emit_finding("panic", "panic signature");
            });

            expect_false!(try_emit_finding("late", "late signature"));
        });

        expect_eq!(
            emitted,
            vec![finding("crash", "crash signature"), finding("panic", "panic signature")]
        );
    }

    #[gtest]
    fn a_second_adapter_is_refused_until_the_first_is_released() {
        let emitted = emitted_by(|| {
            expect_true!(claim_adapter());
            expect_false!(claim_adapter());

            release_adapter();

            expect_true!(claim_adapter());
        });

        expect_that!(emitted, is_empty());
    }

    #[gtest]
    fn emit_error_reaches_the_sink() {
        let emitted = emitted_by(|| {
            let sink = recording_sink();
            // SAFETY: the callbacks of a recording sink may be called at any time.
            unsafe { sink.assume_live() }.emit_error("message");
        });

        expect_eq!(emitted, vec![Emitted::Error("message".to_string())]);
    }

    #[gtest]
    fn try_emit_finding_returns_false_without_blocking_when_state_is_locked() {
        let emitted = emitted_by(|| {
            let sink = recording_sink();
            in_execute_scope(&sink, |_| {
                let guard = PROCESS.lock();
                expect_false!(try_emit_finding("contended", "sig"));
                drop(guard);
                expect_true!(try_emit_finding("uncontended", "sig"));
            });
        });

        expect_eq!(emitted, vec![finding("uncontended", "sig")]);
    }
}
