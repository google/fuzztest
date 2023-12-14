// Copyright 2022 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <dlfcn.h>
#include <stdlib.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

extern "C" {
// Address of FuzzMe() when fuzz_me.so is linked in, nullptr otherwise.
__attribute__((weak)) void FuzzMe(const uint8_t* data,
                                  size_t size);  // From a separate DSO
}

// Reads input files (argv[1:]) one by one and calls FuzzMe() on each file's
// contents.
// If FuzzMe is nullptr at startup, calls dlopen(getenv("FUZZ_ME_PATH"))
// and dlsym() to get the address of FuzzMe().
// When using Centipede with '--binary="./main_executable @@"' only one argument
// will be passed.
// TODO(kcc): if we need to pass more than one input to the main_executable
// while fuzzing, more work needs to be done on the Centipede side.
int main(int argc, char* argv[]) {
  auto Callback = &FuzzMe;
  fprintf(stderr, "Callback: %p\n", Callback);
  if (!Callback) {
    const char* fuzz_me_path = getenv("FUZZ_ME_PATH");
    fprintf(stderr, "Callback is nullptr; doing dlopen(); FUZZ_ME_PATH=%s\n",
            fuzz_me_path);
    auto dl_handle = dlopen(fuzz_me_path, RTLD_NOW);
    if (!dl_handle) {
      fprintf(stderr, "dlopen failed %s\n", dlerror());
      exit(1);
    }
    Callback = (decltype(Callback))dlsym(dl_handle, "FuzzMe");
    fprintf(stderr, "Callback from dlsym(): %p\n", Callback);
  }

  for (int i = 1; i < argc; ++i) {
    std::ifstream file(argv[i], std::ios::in | std::ios::binary);
    std::vector<uint8_t> bytes{std::istream_iterator<uint8_t>(file),
                               std::istream_iterator<uint8_t>()};

    std::cout << bytes.size() << " bytes read from " << argv[i] << "\n";
    // This is where we call into the instrumented DSO.
    Callback(bytes.data(), bytes.size());
  }
}
