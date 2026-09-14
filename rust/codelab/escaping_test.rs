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

use escaping::escape;
use escaping::unescape;
use googletest::prelude::*;

#[gtest]
fn escaping_empty_input_returns_empty_output() {
    expect_that!(escape(b""), eq(b""));
}

#[gtest]
fn unescaping_empty_input_returns_empty_output() {
    expect_that!(unescape(b""), eq(b""));
}

#[gtest]
fn escaping_plain_input_is_returned_as_is() {
    expect_that!(escape(b"plain text"), eq(b"plain text"));
}

#[gtest]
fn unescaping_plain_input_is_returned_as_is() {
    expect_that!(unescape(b"plain text"), eq(b"plain text"));
}

#[gtest]
fn escaping_replaces_special_characters() {
    expect_that!(escape(b"two\nlines"), eq(br"two\nlines"));
    expect_that!(escape(b"back\\slash"), eq(br"back\\slash"));
}

#[gtest]
fn unescaping_replaces_escape_sequences() {
    expect_that!(unescape(br"two\nlines"), eq(b"two\nlines"));
    expect_that!(unescape(br"back\\slash"), eq(b"back\\slash"));
}

// Uncomment the following imports and fuzz tests as you work through the
// codelab.
//
// use fuzztest::domains::arbitrary::Arbitrary;
// use fuzztest::domains::containers::VecOf;
// use fuzztest::fuzztest;

// #[fuzztest(input = VecOf::new(Arbitrary::<u8>::default()))]
// fn unescaping_escaped_input_gives_original(input: Vec<u8>) {
//     assert_eq!(unescape(&escape(&input)), input);
// }

// #[fuzztest(input = VecOf::new(Arbitrary::<u8>::default()))]
// fn escaping_never_panics(input: Vec<u8>) {
//     escape(&input);
// }

// #[fuzztest(input = VecOf::new(Arbitrary::<u8>::default()))]
// fn unescaping_never_panics(input: Vec<u8>) {
//     unescape(&input);
// }
