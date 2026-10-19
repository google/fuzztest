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
use fuzztest::domains::containers::ContainerDomain;
use fuzztest::domains::containers::VecOf;
use fuzztest::domains::range::InRange;
use fuzztest::domains::tuple_of::TupleOf2;
use fuzztest::fuzztest;

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn fuzztest_macro_compiles(_a: i32) {}

#[fuzztest(_a = Arbitrary::<i32>::default(), _b = Arbitrary::<i32>::default())]
fn fuzztest_macro_compiles_with_two_args(_a: i32, _b: i32) {}

#[fuzztest(_a = VecOf::new(Arbitrary::<i32>::default()).with_max_len(10))]
fn fuzztest_macro_compiles_with_vec(_a: Vec<i32>) {}

#[fuzztest(_a = Arbitrary::<Vec<i32>>::default())]
fn fuzztest_macro_compiles_with_arbitrary_vec(_a: Vec<i32>) {}

#[fuzztest(_a = (InRange::new(0i32, 10), Arbitrary::<bool>::default()))]
fn fuzztest_macro_compiles_with_tuple_of(_a: (i32, bool)) {}

#[fuzztest(_a = TupleOf2::from((InRange::new(0i32, 10), Arbitrary::<u8>::default())))]
fn fuzztest_macro_compiles_with_tuple_of_alias(_a: (i32, u8)) {}

#[fuzztest(_a = Arbitrary::<(i32, Vec<u8>)>::default())]
fn fuzztest_macro_compiles_with_arbitrary_tuple(_a: (i32, Vec<u8>)) {}

fn main() {
    // The property function is defined in the scope where the macro is
    // invoked, so it can be called directly, e.g. from a regression test.
    fuzztest_macro_compiles(0);
    fuzztest_macro_compiles_with_arbitrary_vec(vec![1, 2]);
    fuzztest_macro_compiles_with_tuple_of((5, true));
    fuzztest_macro_compiles_with_tuple_of_alias((3, 7));
    fuzztest_macro_compiles_with_arbitrary_tuple((42, vec![1]));
}
