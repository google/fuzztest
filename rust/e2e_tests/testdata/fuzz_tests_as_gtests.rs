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

use fuzztest::domains::arbitrary::Arbitrary;
use fuzztest::fuzztest;
use std::sync::Once;

#[fuzztest(_a = Arbitrary::<bool>::default())]
fn bool_fuzz_test(_a: bool) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        println!("bool_fuzz_test property function ran...");
    });
}

#[fuzztest(
    _a = Arbitrary::<i32>::default(),
    _b = Arbitrary::<f32>::default(),
    _c = Arbitrary::<bool>::default(),
)]
fn multi_arg_fuzz_test(_a: i32, _b: f32, _c: bool) {}

#[fuzztest(a = Arbitrary::<i32>::default())]
fn panicking_fuzz_test(a: i32) {
    assert_eq!(a.wrapping_add(1), a);
}

#[fuzztest(a = Arbitrary::<i32>::default())]
fn expect_failing_fuzz_test(a: i32) {
    googletest::prelude::expect_that!(a.wrapping_add(1), googletest::prelude::eq(a));
}
