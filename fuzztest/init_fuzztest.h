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

// Returns the full name of the fuzz test that "matches" the provided `name`
// specification. If no match is found, it exists.
//
// 1) The provided `name` specification can be a full name, e.g.,
// "MySuite.MyFuzzTest". If such fuzz test exists, the full name is returned.
//
// 2) The `name` specification can also be a strict sub-string of a full name,
// e.g., "MyFuzz". If there's exactly one fuzz test that contains the (strict)
// sub-string, its full name is returned.
//
// 3) The `name` specification can also be an empty string. If there's only one
// fuzz test in the binary, its full name is returned.
//
// If no single match is found, it exits with an error message.
//
// REQUIRES: `main()` has started before calling this function.
std::string GetMatchingFuzzTestOrExit(std::string_view name);

// Runs the FUZZ_TEST specified by `name` in fuzzing mode.
//
// Selects the fuzz test to run using GetMatchingFuzzTestOrExit(name).
//
// If `name` matches exactly one FUZZ_TEST, it runs the selected test in fuzzing
// mode, until a bug is found or until manually stopped. Otherwise, it exits.
//
// REQUIRES: `main()` has started before calling this function.
// REQUIRES: Binary must be built with SanCov instrumentation on.
void RunSpecifiedFuzzTest(std::string_view name);

}  // namespace fuzztest

#endif  // FUZZTEST_FUZZTEST_INIT_FUZZTEST_H_
