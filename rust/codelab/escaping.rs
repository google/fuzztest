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

//! A tiny escaping library used by the Rust FuzzTest codelab.
//!
//! It converts special characters in a byte string into C-style escape
//! sequences and back.
//!
//! The library intentionally contains two bugs that the codelab's fuzz tests
//! are meant to discover, so please don't "fix" them.

/// Returns `input` with special characters replaced by C-style escape
/// sequences.
pub fn escape(input: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(input.len());
    for &byte in input {
        match byte {
            b'\n' => result.extend_from_slice(br"\n"),
            b'\r' => result.extend_from_slice(br"\r"),
            b'\t' => result.extend_from_slice(br"\t"),
            b'\\' => result.extend_from_slice(br"\\"),
            _ => result.push(byte),
        }
    }
    result
}

/// Returns `input` with C-style escape sequences replaced by the characters
/// they represent.
///
/// Unrecognized escape sequences are dropped.
pub fn unescape(input: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'\\' {
            i += 1;
            match input[i] {
                b'n' => result.push(b'\n'),
                b't' => result.push(b'\t'),
                b'\\' => result.push(b'\\'),
                _ => {}
            }
        } else {
            result.push(input[i]);
        }
        i += 1;
    }
    result
}
