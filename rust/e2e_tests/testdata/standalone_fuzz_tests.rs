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

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn standalone_validation_test(_a: i32) {
    // Minimal test function to validate standalone mode.
    println!("STANDALONE_VALIDATION_WORKER_EXECUTED");
    println!("STANDALONE_VALIDATION_INPUT: {}", _a);
}

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn second_validation_test(_a: i32) {
    println!("SECOND_VALIDATION_TEST_EXECUTED");
    println!("SECOND_VALIDATION_INPUT: {}", _a);
}

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn jobs_test(_a: i32) {
    println!("JOBS_TEST_PID: {}", std::process::id());
    std::thread::sleep(std::time::Duration::from_millis(250));
}
