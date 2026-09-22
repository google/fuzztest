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

// SAFETY:
// - `FuzzTestSetSanitizerErrorSummaryCallback` is declared with `extern "C"` linkage in
//   `internal/sanitizer_interface.h` and defined in `internal/sanitizer_interface.cc`.
// - The signature matches `void FuzzTestSetSanitizerErrorSummaryCallback(void (*)(const char*, size_t))`:
//   `*const u8` is layout- and ABI-compatible with `const char*`, and `usize` is ABI-compatible
//   with `size_t`.
unsafe extern "C" {
    fn FuzzTestSetSanitizerErrorSummaryCallback(
        callback: unsafe extern "C" fn(crash_type_data: *const u8, crash_type_size: usize),
    );
}

/// Sanitizer error summary callback invoked by the C++ sanitizer interface.
///
/// # Safety
///
/// The caller must uphold the following preconditions:
/// - If `crash_type_size > 0`, `crash_type_data` must be non-null and valid for reads of
///   `crash_type_size` consecutive, initialized `u8` bytes for the duration of the call.
/// - The pointed-to memory must not be mutated concurrently for the duration of the call.
/// - `crash_type_size` must not exceed `isize::MAX`.
unsafe extern "C" fn sanitizer_error_summary_callback(
    crash_type_data: *const u8,
    crash_type_size: usize,
) {
    let crash_type = if crash_type_data.is_null() || crash_type_size == 0 {
        "Sanitizer crash"
    } else {
        // SAFETY:
        // - Non-nullness: `crash_type_data` was verified non-null above.
        // - Alignment: `u8` has alignment 1, so any non-null pointer is properly aligned.
        // - Validity: The caller guarantees `crash_type_data` points to `crash_type_size`
        //   consecutive, initialized `u8` bytes valid for reads for the duration of this call.
        // - Aliasing: The pointed-to memory is read-only and not mutated during the call.
        // - Size: The caller guarantees `crash_type_size <= isize::MAX`.
        let crash_type_bytes =
            unsafe { std::slice::from_raw_parts(crash_type_data, crash_type_size) };
        std::str::from_utf8(crash_type_bytes).unwrap_or("Sanitizer crash (invalid utf8)")
    };
    crate::worker::try_emit_finding(crash_type, crash_type);
}

/// Registers the sanitizer error summary callback and ensures the sanitizer crash handler hook is
/// linked into the binary.
pub fn register_crash_handler() {
    // SAFETY:
    // - `sanitizer_error_summary_callback` is an `unsafe extern "C" fn` matching the C callback
    //   signature `FuzzTestSanitizerErrorSummaryCallback` (`void (*)(const char*, size_t)`).
    // - As a function item, `sanitizer_error_summary_callback` has `'static` lifetime and remains
    //   valid for the entire duration of program execution.
    // - `FuzzTestSetSanitizerErrorSummaryCallback` stores the function pointer in a `std::atomic`
    //   using `memory_order_relaxed`, so concurrent registration is data-race free.
    unsafe {
        FuzzTestSetSanitizerErrorSummaryCallback(sanitizer_error_summary_callback);
    }
}
