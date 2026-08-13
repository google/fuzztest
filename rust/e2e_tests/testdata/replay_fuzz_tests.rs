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

#[fuzztest(a = Arbitrary::<i32>::default())]
fn find_bug_fuzz_test(a: i32) {
    println!("PROPERTY_FUNCTION_EXECUTED");
    if a == 10 || a == 20 || a == 30 {
        panic!("Bug found!");
    }
}

#[fuzztest(a = Arbitrary::<i32>::default())]
fn find_two_bugs_fuzz_test(a: i32) { println!("PROPERTY_FUNCTION_EXECUTED");
    if a == 10 {
        panic!("Bug 1 found!");
    } else if a == 20 {
        println!("Bug 2 found!");
        std::process::exit(99);
    }
}

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn untargeted_test_1(_a: i32) {
    println!("UNTARGETED_TEST_1_EXECUTED");
}

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn untargeted_test_2(_a: i32) {
    println!("UNTARGETED_TEST_2_EXECUTED");
}
