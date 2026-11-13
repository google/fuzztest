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

//! Metadata registry for fuzz tests registered via the `#[fuzztest]` macro.

#![deny(clippy::absolute_paths)]
#![deny(unused_imports)]

/// Identifies the property function of a fuzz test.
///
/// `FuzzTestInfo` is instantiated by the `#[fuzztest]` macro, which populates the fields with the
/// source location and module path of the test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// Entry submitted to `inventory` for each registered fuzz test in the binary.
#[derive(Clone, Copy, Debug)]
pub struct FuzzTestRegistration {
    pub info: &'static FuzzTestInfo,
}

inventory::collect!(FuzzTestRegistration);

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;

    #[gtest]
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
}
