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
}

impl FuzzTestInfo {
    /// Returns the fully qualified test name (e.g.,
    /// `escaping_test::__fuzztest_mod__unescaping_never_panics::unescaping_never_panics`).
    pub fn full_test_name(&self) -> String {
        format!("{}::{}", self.module_path, self.name)
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
    eprint!("{}", format_finding_report(info, formatted_args));
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

    #[googletest::test]
    fn test_full_test_name_includes_crate_and_module_path() {
        let info = FuzzTestInfo {
            name: "unescaping_never_panics",
            module_path: "escaping_test::__fuzztest_mod__unescaping_never_panics",
            file: "third_party/googlefuzztest/rust/codelab/escaping_test.rs",
            line: 72,
        };
        expect_that!(
            info.full_test_name(),
            eq("escaping_test::__fuzztest_mod__unescaping_never_panics::unescaping_never_panics")
        );
    }

    #[googletest::test]
    fn test_format_finding_report_matches_expected_format() {
        let info = FuzzTestInfo {
            name: "test_name",
            module_path: "crate_name::module_name",
            file: "FILE",
            line: 123,
        };
        let args =
            vec![format_debug_arg(format!("{:?}", 17)), format_debug_arg(format!("{:?}", "ABC"))];
        let report = format_finding_report(&info, &args);
        expect_that!(
            report,
            eq(concat!(
                "\n=================================================================\n",
                "=== BUG FOUND!\n\n",
                "FILE:123: Counterexample found for crate_name::module_name::test_name.\n",
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
}
