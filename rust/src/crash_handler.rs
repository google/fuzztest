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

unsafe extern "C" {
    fn FuzzTestSetSanitizerErrorSummaryCallback(
        callback: unsafe extern "C" fn(crash_type_data: *const u8, crash_type_size: usize),
    );
}

unsafe extern "C" fn sanitizer_error_summary_callback(
    crash_type_data: *const u8,
    crash_type_size: usize,
) {
    // SAFETY: `FuzzTestSetSanitizerErrorSummaryCallback` guarantees `crash_type_data`
    // and `crash_type_size` form a valid ASCII byte slice for the duration of the callback.
    let crash_type_bytes = unsafe { std::slice::from_raw_parts(crash_type_data, crash_type_size) };
    let crash_type = std::str::from_utf8(crash_type_bytes).unwrap_or("Sanitizer crash");
    crate::worker::try_emit_finding(crash_type, crash_type);
}

/// Registers the sanitizer error summary callback and ensures the sanitizer crash handler hook is
/// linked into the binary.
pub fn register_crash_handler() {
    // SAFETY: `sanitizer_error_summary_callback` is a valid function pointer with C ABI.
    unsafe {
        FuzzTestSetSanitizerErrorSummaryCallback(sanitizer_error_summary_callback);
    }
}
