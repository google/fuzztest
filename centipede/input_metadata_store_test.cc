// Copyright 2026 The Centipede Authors.
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

#include "./centipede/input_metadata_store.h"

#include <cstddef>
#include <filesystem>  // NOLINT
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./centipede/environment.h"
#include "./centipede/runner_result.h"
#include "./common/defs.h"
#include "./common/hash.h"
#include "./common/remote_file.h"
#include "./common/test_util.h"

namespace fuzztest::internal {
namespace {

using ::testing::ElementsAre;
using ::testing::IsEmpty;

Environment EnvWithRoot(const std::string& root) {
  Environment env;
  env.fuzztest_persistent_metadata_root = root;
  env.fuzztest_binary_identifier = "some/binary";
  env.test_name = "Suite.Test";
  return env;
}

// Saves to `store` the results of executing `inputs`, with `metadata[i]` as the
// persistent metadata of the result of `inputs[i]`. Only the first
// `num_outputs_read` results count as read.
void SaveResults(InputMetadataStore& store, const std::vector<ByteSpan>& inputs,
                 const std::vector<ByteArray>& metadata,
                 size_t num_outputs_read) {
  BatchResult batch_result;
  batch_result.ClearAndResize(metadata.size());
  for (size_t i = 0; i < metadata.size(); ++i) {
    batch_result.results()[i].metadata().persistent_data = metadata[i];
  }
  batch_result.num_outputs_read() = num_outputs_read;
  store.Save(inputs, batch_result);
}

void SaveResults(InputMetadataStore& store, const std::vector<ByteSpan>& inputs,
                 const std::vector<ByteArray>& metadata) {
  SaveResults(store, inputs, metadata, metadata.size());
}

TEST(InputMetadataStore, IsDisabledWithoutARoot) {
  const Environment env = EnvWithRoot("");
  InputMetadataStore store(env);
  const ByteArray input = {1};

  EXPECT_FALSE(store.enabled());
  EXPECT_THAT(store.Load({input}), IsEmpty());
  // Must not crash or write anything.
  SaveResults(store, {input}, {{7}});
}

TEST(InputMetadataStore, UsesAPerBinaryAndPerTestDirectory) {
  const Environment env = EnvWithRoot("/root");
  InputMetadataStore store(env);

  EXPECT_TRUE(store.enabled());
  EXPECT_EQ(store.dir(), "/root/some/binary/Suite.Test");
}

TEST(InputMetadataStore, LoadsWhatWasSavedForTheSameInputBytes) {
  TempDir temp_dir{test_info_->name()};
  const Environment env = EnvWithRoot(temp_dir.path().string());
  const ByteArray in0 = {1, 2};
  const ByteArray in1 = {3};
  const ByteArray in2 = {4, 5, 6};
  const ByteArray metadata0 = {'a', 0, 'b'};
  const ByteArray metadata2 = {'c'};

  {
    InputMetadataStore store(env);
    // Nothing is stored yet.
    EXPECT_THAT(store.Load({in0, in1, in2}),
                ElementsAre(IsEmpty(), IsEmpty(), IsEmpty()));
    // Input 1 returns no persistent metadata.
    SaveResults(store, {in0, in1, in2}, {metadata0, {}, metadata2});
  }

  // A new store (e.g. of a later run) sees the stored metadata, keyed by the
  // input bytes and regardless of the order.
  InputMetadataStore store(env);
  EXPECT_THAT(store.Load({in2, in1, in0}),
              ElementsAre(metadata2, IsEmpty(), metadata0));
  EXPECT_TRUE(RemotePathExists(
      (std::filesystem::path(store.dir()) / Hash(in0)).string()));
  EXPECT_FALSE(RemotePathExists(
      (std::filesystem::path(store.dir()) / Hash(in1)).string()));
}

TEST(InputMetadataStore, KeepsStoredMetadataWhenAResultHasNone) {
  TempDir temp_dir{test_info_->name()};
  const Environment env = EnvWithRoot(temp_dir.path().string());
  InputMetadataStore store(env);
  const ByteArray input = {1, 2};
  const ByteArray metadata = {'a'};

  SaveResults(store, {input}, {metadata});
  SaveResults(store, {input}, {{}});

  EXPECT_THAT(store.Load({input}), ElementsAre(metadata));
}

TEST(InputMetadataStore, OverwritesStoredMetadataWithNewMetadata) {
  TempDir temp_dir{test_info_->name()};
  const Environment env = EnvWithRoot(temp_dir.path().string());
  InputMetadataStore store(env);
  const ByteArray input = {1, 2};
  const ByteArray new_metadata = {'n', 'e', 'w'};

  SaveResults(store, {input}, {{'o', 'l', 'd'}});
  SaveResults(store, {input}, {new_metadata});

  EXPECT_THAT(store.Load({input}), ElementsAre(new_metadata));
}

TEST(InputMetadataStore, SavesOnlyTheResultsThatWereRead) {
  TempDir temp_dir{test_info_->name()};
  const Environment env = EnvWithRoot(temp_dir.path().string());
  InputMetadataStore store(env);
  const ByteArray in0 = {1};
  const ByteArray in1 = {2};
  const ByteArray metadata0 = {'a'};

  // The second input was not executed (e.g. the first one crashed after its
  // result was written), so its result slot must be ignored.
  SaveResults(store, {in0, in1}, {metadata0, {'x'}}, /*num_outputs_read=*/1);

  EXPECT_THAT(store.Load({in0, in1}), ElementsAre(metadata0, IsEmpty()));
}

}  // namespace
}  // namespace fuzztest::internal
