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
use fuzztest::domains::SeedableDomain;
use fuzztest::fuzztest;

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn fuzztest_macro_compiles(_a: i32) {}

#[fuzztest(_a = Arbitrary::<i32>::default(), _b = Arbitrary::<i32>::default())]
fn fuzztest_macro_compiles_with_two_args(_a: i32, _b: i32) {}

#[fuzztest(_a = VecOf::new(Arbitrary::<i32>::default()).with_max_len(10))]
fn fuzztest_macro_compiles_with_vec(_a: Vec<i32>) {}

#[fuzztest(_a = Arbitrary::<i32>::default().with_seeds([1, 2, 3]))]
fn fuzztest_macro_compiles_with_seeds(_a: i32) {}

#[fuzztest(_a = Arbitrary::<i32>::default().with_seed_provider(|| vec![1, 2, 3]))]
fn fuzztest_macro_compiles_with_seed_provider(_a: i32) {}

#[fuzztest(_a = VecOf::new(Arbitrary::<i32>::default()).with_seeds(vec![vec![1, 2, 3]]))]
fn fuzztest_macro_compiles_with_vec_seeds(_a: Vec<i32>) {}

fn main() {}
