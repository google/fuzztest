#ifndef FUZZTEST_FUZZTEST_INIT_FUZZTEST_H_
#define FUZZTEST_FUZZTEST_INIT_FUZZTEST_H_

#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace fuzztest {

// Initializes FuzzTest. Handles the FuzzTest related flags and registers
// FUZZ_TEST-s in the binary as GoogleTest TEST-s.
//
// The command line arguments (argc, argv) are passed only to support the
// "compatibility mode" with external engines via the LLVMFuzzerRunDriver
// interface:
// https://llvm.org/docs/LibFuzzer.html#using-libfuzzer-as-a-library
//
// REQUIRES: `main()` has started before calling this function.
void InitFuzzTest(int* argc, char*** argv);

// Returns a list of all registered fuzz test names in the form of
// "<suite_name>.<property_function_name>", e.g., `MySuite.MyFuzzTest".
//
// REQUIRES: `main()` has started before calling this function.
std::vector<std::string> ListRegisteredTests();

// Returns the full name of the single registered fuzz test that matches `name`.
// If there are zero or multiple tests that match `name`, exits with an error
// message.
//
// A test matches `name` if its full name (e.g., "MySuite.MyFuzzTest") contains
// `name` (e.g., "MyFuzz") as a substring. If there is a test whose full name
// exactly matches `name`, then this will be the returned name.
//
// REQUIRES: `main()` has started before calling this function.
std::string GetMatchingFuzzTestOrExit(std::string_view name);

// Runs the FUZZ_TEST specified by `name` in fuzzing mode.
//
// The `name` can be a full name, e.g., "MySuite.MyFuzzTest". It can also be a
// part of the full name, e.g., "MyFuzz", if it matches only a single fuzz test
// in the binary. If there is only one fuzz test in binary, name can also be
// empty string. If `name` matches exactly one FUZZ_TEST, it runs the selected
// test in fuzzing mode, until a bug is found or until manually stopped.
// Otherwise, it exits.
//
// REQUIRES: `main()` has started before calling this function.
// REQUIRES: Binary must be built with SanCov instrumentation on.
void RunSpecifiedFuzzTest(std::string_view name);

}  // namespace fuzztest

#endif  // FUZZTEST_FUZZTEST_INIT_FUZZTEST_H_
