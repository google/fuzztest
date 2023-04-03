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

// A test fuzz target that has lots of threads in it, including some threads
// that start and join at weird times.

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <thread>  // NOLINT

namespace {

// Starts and joins a thread, returns true.
bool CreateAndJoinAThread() {
  const auto *parent_func = __func__;
  std::thread t([parent_func]() {
    std::cerr << parent_func << "::" << __func__ << " " << std::endl;
  });
  t.join();
  return true;
}

[[maybe_unused]] bool start_and_join_two_threads_before_main[2] = {
    CreateAndJoinAThread(), CreateAndJoinAThread()};

void BackgroundThread() {
  std::cerr << __func__ << " " << std::endl;
  while (true) {
    std::thread another_thread([]() {});
    another_thread.join();
  }
}

// overlapping_thread is created in one call to LLVMFuzzerTestOneInput()
// and joined in the following call to LLVMFuzzerTestOneInput(), and so on.
std::thread *overlapping_thread;

volatile int sink;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Create the Background Thread on first entry.
  [[maybe_unused]] static auto *background_thread =
      new std::thread(BackgroundThread);

  if (overlapping_thread) {
    overlapping_thread->join();
    overlapping_thread = nullptr;
  } else {
    overlapping_thread =
        new std::thread([]() { std::cerr << "weird thread" << std::endl; });
  }

  // All interesting code runs inside a freshly-created thread.
  std::thread worker([&]() {
    // Just some control flow.
    if (size >= 4 && data[0] == 'f' && data[1] == 'u' && data[2] == 'z' &&
        data[3] == 'z') {
      sink = 1;
    }
  });
  worker.join();

  return 0;
}
