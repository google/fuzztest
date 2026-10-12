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

use super::domains::GenericCorpusValue;
use super::domains::GenericDomain;
use std::collections::HashMap;
use std::fmt::Write;
use std::marker::PhantomData;
use std::mem;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;

const REPORT_SEPARATOR: &str = "=================================================================";
const VALUE_MAX_PRINT_LENGTH: usize = 2048;

/// A trait implemented by types used to Fuzz a given property function.
///
/// When a test is annotated with the `fuzztest` macro attribute, that test will be wrapped in a
/// FuzzTestObject that implements this trait. The FuzzTestObject is created by the macro and holds,
/// among others, the property function and the domains of its arguments.
/// The FuzzTestObject is then manipulated by Fuzzing Test Engine through the APIs of this trait.
pub trait FuzzTest {
    // TODO(tinmar): refine arguments as we get a clearer picture of
    // what the dispatcher interface looks like
    fn name(&self) -> &'static str;
    fn activate(&mut self);
    fn mutate(&mut self);
    /// Executes the property function with the given arguments
    /// (will attempt to downcast to actual user values).
    ///
    /// Returns `true` if the property function holds, `false` if it crashes.
    fn execute(&self, args: &GenericCorpusValue) -> bool;
    /// Formats and prints the counterexample finding report for `args` to `stderr`.
    fn print_finding_report(&self, args: &GenericCorpusValue);
    /// Returns the static metadata identifying this fuzz test.
    fn info(&self) -> &'static FuzzTestInfo;
    fn domains(&self) -> Arc<Mutex<dyn GenericDomain>>;
}

/// Identifies the property function of a fuzz test.
///
/// `FuzzTestInfo` is instantiated by the `fuzztest` macro which populates the fields with the
/// appropriate values.
pub struct FuzzTestInfo {
    pub name: &'static str,
    pub module_path: &'static str,
    pub file: &'static str,
    pub line: u32,
    pub column: u32,
}

impl FuzzTestInfo {
    /// Returns the formatted test name (e.g.,
    /// `__fuzztest_mod__unescaping_never_panics::unescaping_never_panics`).
    pub fn full_test_name(&self) -> String {
        let full = format!("{}::{}", self.module_path, self.name);
        full.split_once("::").map_or(full.as_str(), |(_, rest)| rest).to_string()
    }
}

/// Truncates a `Debug`-formatted argument string if it exceeds `VALUE_MAX_PRINT_LENGTH` bytes.
pub fn format_debug_arg(mut formatted: String) -> String {
    if formatted.len() > VALUE_MAX_PRINT_LENGTH {
        let mut end = VALUE_MAX_PRINT_LENGTH;
        while !formatted.is_char_boundary(end) {
            end -= 1;
        }
        formatted.truncate(end);
        formatted.push_str(" ...<value too long>");
    }
    formatted
}

/// Formats the `=== BUG FOUND!` finding report block for the given fuzz test and formatted
/// arguments.
pub fn format_finding_report(info: &FuzzTestInfo, formatted_args: &[String]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n{REPORT_SEPARATOR}");
    let _ = writeln!(out, "=== BUG FOUND!\n");
    let _ = writeln!(
        out,
        "{}:{}: Counterexample found for {}.",
        info.file,
        info.line,
        info.full_test_name()
    );
    let _ = writeln!(out, "The test fails with input:");
    for (idx, arg) in formatted_args.iter().enumerate() {
        let _ = writeln!(out, "argument {idx}: {arg}");
    }
    let _ = writeln!(out, "\n{REPORT_SEPARATOR}");
    out
}

/// Prints the `=== BUG FOUND!` finding report block to `stderr`.
pub fn print_finding_report(info: &FuzzTestInfo, formatted_args: &[String]) {
    let _ = std::io::Write::write_all(
        &mut std::io::stderr(),
        format_finding_report(info, formatted_args).as_bytes(),
    );
}

struct FindingReportContext {
    fuzz_test: *const dyn FuzzTest,
    input: *const GenericCorpusValue,
    // Tracks whether the finding report has already been printed for the current execution so we
    // don't print duplicate `=== BUG FOUND!` blocks if the sanitizer error summary hook is invoked
    // multiple times for a single crash.
    report_printed: bool,
}

thread_local! {
    /// A thread-local context holding the currently executing fuzz test and input for printing
    /// the `=== BUG FOUND!` counterexample report from sanitizer crash callbacks.
    ///
    /// Thread-local storage is necessary because C callbacks (e.g. sanitizer hooks in
    /// `crash_handler.rs`) do not have access to the fuzz test or input, and in smoke-test mode
    /// `libtest` runs multiple fuzz tests concurrently on separate threads. Wrapping in `Mutex`
    /// allows same-thread sanitizer callbacks to use `try_lock()` safely without risking a
    /// reentrancy panic.
    static FINDING_REPORT_CONTEXT: spin::Mutex<Option<FindingReportContext>> =
        const { spin::Mutex::new(None) };
}

/// A guard that manages the thread-local `FINDING_REPORT_CONTEXT` state, setting it to `Some` on
/// creation, and resetting to `None` on drop.
#[must_use = "the finding report guard must be held for the duration of the test execution to print counterexample reports on crashes"]
struct FindingReportGuard {
    // Ensures `FindingReportGuard` is `!Send` so it is always dropped on the same thread that
    // entered it, clearing that thread's `FINDING_REPORT_CONTEXT`.
    _not_send: PhantomData<*const ()>,
}

impl FindingReportGuard {
    /// Enters the finding report context by setting `FINDING_REPORT_CONTEXT` on the current thread.
    ///
    /// # Safety
    ///
    /// * `fuzz_test` and `input` must remain valid for shared borrows for the entire lifetime of
    ///   the returned `FindingReportGuard`.
    /// * The returned `FindingReportGuard` must be dropped (not forgotten) before `fuzz_test` or
    ///   `input` is invalidated.
    unsafe fn enter(fuzz_test: &dyn FuzzTest, input: &GenericCorpusValue) -> Self {
        // SAFETY: `*const (dyn FuzzTest + '_)` and `*const (dyn FuzzTest + 'static)` have the
        // exact same fat-pointer layout; erasing the lifetime on the raw pointer is sound because
        // the caller guarantees `fuzz_test` remains valid until this guard is dropped.
        let fuzz_test_ptr: *const (dyn FuzzTest + 'static) =
            unsafe { mem::transmute(fuzz_test as *const dyn FuzzTest) };
        FINDING_REPORT_CONTEXT.with(|ctx| {
            *ctx.lock() = Some(FindingReportContext {
                fuzz_test: fuzz_test_ptr,
                input: input as *const GenericCorpusValue,
                report_printed: false,
            });
        });
        Self { _not_send: PhantomData }
    }
}

impl Drop for FindingReportGuard {
    fn drop(&mut self) {
        let _ = FINDING_REPORT_CONTEXT.try_with(|ctx| {
            *ctx.lock() = None;
        });
    }
}

/// Runs `f` with the thread-local `FINDING_REPORT_CONTEXT` set to `fuzz_test` and `input`,
/// ensuring that sanitizer crash callbacks invoked during `f` can print the counterexample report
/// and that the context is cleared when `f` returns or unwinds.
pub fn with_finding_report_context<R>(
    fuzz_test: &dyn FuzzTest,
    input: &GenericCorpusValue,
    f: impl FnOnce() -> R,
) -> R {
    // SAFETY: `fuzz_test` and `input` are borrowed for the entire body of
    // `with_finding_report_context`, and `_report_guard` is a stack-local variable that cannot be
    // forgotten by `f` and is dropped before this function returns or unwinds.
    let _report_guard = unsafe { FindingReportGuard::enter(fuzz_test, input) };
    f()
}

/// Prints the finding report if we are currently in an active finding report context on the
/// current thread and have not yet printed a report for this execution.
/// It only tries once to acquire the lock on `FINDING_REPORT_CONTEXT`.
pub(crate) fn try_print_finding_report() -> bool {
    FINDING_REPORT_CONTEXT
        .try_with(|ctx| {
            let Some(mut report_guard) = ctx.try_lock() else {
                return false;
            };
            let Some(active_exec) = report_guard.as_mut() else {
                return false;
            };
            if active_exec.report_printed {
                return false;
            }
            active_exec.report_printed = true;
            // SAFETY: While `FINDING_REPORT_CONTEXT` is `Some` on this thread, `fuzz_test` and
            // `input` point to live values borrowed by an active `with_finding_report_context`
            // frame on the current thread's stack, and no mutable references to them exist.
            unsafe {
                (*active_exec.fuzz_test).print_finding_report(&*active_exec.input);
            }
            true
        })
        .unwrap_or(false)
}

pub type BoxedFuzzTest = Box<dyn FuzzTest + Send + Sync>;

pub struct FuzzTestRegistration {
    pub info: &'static FuzzTestInfo,
    pub factory: fn() -> BoxedFuzzTest,
}

inventory::collect!(FuzzTestRegistration);

#[allow(clippy::type_complexity)]
pub static FUZZ_TEST_NAME_TO_FACTORY: LazyLock<HashMap<&str, fn() -> BoxedFuzzTest>> =
    LazyLock::new(|| {
        inventory::iter
            .into_iter()
            .map(|&FuzzTestRegistration { info, factory }| (info.name, factory))
            .collect()
    });

pub struct InputStateAndDomain<I, D> {
    pub input_state: Option<I>,
    pub domain: D,
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingFuzzTest {
        print_count: AtomicUsize,
    }

    impl FuzzTest for CountingFuzzTest {
        fn name(&self) -> &'static str {
            "counting_fuzz_test"
        }
        fn activate(&mut self) {}
        fn mutate(&mut self) {}
        fn execute(&self, _args: &GenericCorpusValue) -> bool {
            true
        }
        fn print_finding_report(&self, _args: &GenericCorpusValue) {
            self.print_count.fetch_add(1, Ordering::Relaxed);
        }
        fn info(&self) -> &'static FuzzTestInfo {
            unimplemented!()
        }
        fn domains(&self) -> Arc<Mutex<dyn GenericDomain>> {
            unimplemented!()
        }
    }

    #[googletest::test]
    fn test_full_test_name_strips_crate_prefix() {
        let info = FuzzTestInfo {
            name: "unescaping_never_panics",
            module_path: "escaping_test::__fuzztest_mod__unescaping_never_panics",
            file: "third_party/googlefuzztest/rust/codelab/escaping_test.rs",
            line: 72,
            column: 1,
        };
        expect_that!(
            info.full_test_name(),
            eq("__fuzztest_mod__unescaping_never_panics::unescaping_never_panics")
        );
    }

    #[googletest::test]
    fn test_format_finding_report_matches_expected_format() {
        let info = FuzzTestInfo {
            name: "TEST_NAME",
            module_path: "crate_name::SUITE_NAME",
            file: "FILE",
            line: 123,
            column: 1,
        };
        let args =
            vec![format_debug_arg(format!("{:?}", 17)), format_debug_arg(format!("{:?}", "ABC"))];
        let report = format_finding_report(&info, &args);
        expect_that!(
            report,
            eq(concat!(
                "\n=================================================================\n",
                "=== BUG FOUND!\n\n",
                "FILE:123: Counterexample found for SUITE_NAME::TEST_NAME.\n",
                "The test fails with input:\n",
                "argument 0: 17\n",
                "argument 1: \"ABC\"\n\n",
                "=================================================================\n",
            ))
        );
    }

    #[googletest::test]
    fn test_format_debug_arg_truncates_long_values_at_char_boundary() {
        let long_str = "é".repeat(1500);
        let formatted = format_debug_arg(long_str);
        expect_that!(formatted, ends_with(" ...<value too long>"));
        expect_that!(formatted.len(), le(VALUE_MAX_PRINT_LENGTH + " ...<value too long>".len()));
    }

    #[googletest::test]
    fn test_try_print_finding_report_prints_only_once_per_execution() {
        let fuzz_test = CountingFuzzTest { print_count: AtomicUsize::new(0) };
        let input: GenericCorpusValue = Box::new(42i32);

        // Outside `with_finding_report_context`, nothing should be printed.
        expect_that!(try_print_finding_report(), eq(false));
        expect_that!(fuzz_test.print_count.load(Ordering::Relaxed), eq(0));

        with_finding_report_context(&fuzz_test, &input, || {
            expect_that!(try_print_finding_report(), eq(true));
            expect_that!(try_print_finding_report(), eq(false));
            expect_that!(fuzz_test.print_count.load(Ordering::Relaxed), eq(1));
        });

        // After `with_finding_report_context` returns, the context is cleared.
        expect_that!(try_print_finding_report(), eq(false));

        // Entering a new execution resets `report_printed`.
        with_finding_report_context(&fuzz_test, &input, || {
            expect_that!(try_print_finding_report(), eq(true));
            expect_that!(fuzz_test.print_count.load(Ordering::Relaxed), eq(2));
        });
    }

    #[googletest::test]
    fn test_with_finding_report_context_is_isolated_per_thread() {
        let fuzz_test = CountingFuzzTest { print_count: AtomicUsize::new(0) };
        let input: GenericCorpusValue = Box::new(42i32);

        with_finding_report_context(&fuzz_test, &input, || {
            // Entering and exiting `with_finding_report_context` on another thread must not
            // clobber or clear the current thread's `FINDING_REPORT_CONTEXT`.
            std::thread::spawn(|| {
                let other_test = CountingFuzzTest { print_count: AtomicUsize::new(0) };
                let other_input: GenericCorpusValue = Box::new(99i32);
                with_finding_report_context(&other_test, &other_input, || {});
            })
            .join()
            .unwrap();

            expect_that!(try_print_finding_report(), eq(true));
            expect_that!(fuzz_test.print_count.load(Ordering::Relaxed), eq(1));
        });
    }
}
