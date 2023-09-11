#ifndef FUZZTEST_FUZZTEST_INIT_FUZZTEST_H_
#define FUZZTEST_FUZZTEST_INIT_FUZZTEST_H_

namespace fuzztest {

// Handles FuzzTest related flags and registers FUZZ_TEST-s in the binary as
// GoogleTest TEST-s.
//
// The command line arguments (argc, argv) are passed only to support the
// "compatibility mode" with external engines via the LLVMFuzzerRunDriver
// interface:
// https://llvm.org/docs/LibFuzzer.html#using-libfuzzer-as-a-library
void InitFuzzTest(int* argc, char*** argv);

}  // namespace fuzztest

#endif  // FUZZTEST_FUZZTEST_INIT_FUZZTEST_H_
