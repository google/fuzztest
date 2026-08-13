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

#[cfg(any(sanitize = "address", sanitize = "memory"))]
mod callbacks {
    use std::ffi::{c_char, CStr};

    unsafe extern "C" {
        pub safe fn __sanitizer_set_death_callback(callback: Option<extern "C" fn()>);

        pub safe fn __asan_get_report_description() -> *const c_char;
    }

    pub extern "C" fn sanitizer_death_callback() {
        use crate::worker;

        let (description, signature) = if cfg!(sanitize = "address") {
            let char_ptr = __asan_get_report_description();
            // Safety: `ptr` points to a valid null terminated string.
            let signature_cstr = unsafe { CStr::from_ptr(char_ptr) };
            (
                "Property function ran but address sanitizer caught a bug",
                signature_cstr.to_str().unwrap_or("ASan crash"),
            )
        } else {
            ("Property function ran but a sanitizer caught a bug", "Sanitizer crash")
        };
        worker::try_emit_finding(description, signature);
    }
}

/// Be able to emit failures before exiting fully from the process for non-unwinding panics and/or
/// unrecoverable crashes.
pub fn register_crash_handler() {
    // TODO(yamilmorales): Consider allowing more sanitizers here, and find some other way to
    // recognize sanitizers if this feature is not stabilized by the time we need to support Cargo.
    #[cfg(any(sanitize = "address", sanitize = "memory"))]
    {
        callbacks::__sanitizer_set_death_callback(Some(callbacks::sanitizer_death_callback));
    }
}
