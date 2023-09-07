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

// TODO(ussuri): This module has become a catch-all for all sorts of utils.
//  Split it by category.

#include "./centipede/util.h"

#include <linux/limits.h>  // NOLINT(PATH_MAX)
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>  // NOLINT(popen)
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>  // NOLINT
#include <fstream>
#include <queue>
#include <string>
#include <string_view>
#include <thread>  // NOLINT(build/c++11)
#include <utility>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/base/const_init.h"
#include "absl/base/thread_annotations.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/str_split.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/span.h"
#include "./centipede/defs.h"
#include "./centipede/feature.h"
#include "./centipede/logging.h"

namespace centipede {

static_assert(kPathMax >= PATH_MAX, "kPathMax is too small.");

size_t GetRandomSeed(size_t seed) {
  if (seed != 0) return seed;
  return time(nullptr) + getpid() +
         std::hash<std::thread::id>{}(std::this_thread::get_id());
}

std::string AsString(const ByteArray &data, size_t max_len) {
  std::ostringstream out;
  size_t len = std::min(max_len, data.size());
  for (size_t i = 0; i < len; ++i) {
    const auto ch = data[i];
    if (std::isprint(ch)) {
      out << ch;
    } else {
      out << "\\x" << std::uppercase << std::hex << static_cast<uint32_t>(ch);
    }
  }
  return out.str();
}

template <typename Container>
void ReadFromLocalFile(std::string_view file_path, Container &data) {
  std::ifstream f(std::string{file_path});
  if (!f) return;
  f.seekg(0, std::ios_base::end);
  auto size = f.tellg();
  f.seekg(0, std::ios_base::beg);
  CHECK_EQ(size % sizeof(data[0]), 0);
  data.resize(size / sizeof(data[0]));
  f.read(reinterpret_cast<char *>(data.data()), size);
  CHECK(f) << "Failed to read from local file: " << file_path;
  f.close();
}

void ReadFromLocalFile(std::string_view file_path, std::string &data) {
  return ReadFromLocalFile<std::string>(file_path, data);
}
void ReadFromLocalFile(std::string_view file_path, ByteArray &data) {
  return ReadFromLocalFile<ByteArray>(file_path, data);
}
void ReadFromLocalFile(std::string_view file_path, FeatureVec &data) {
  return ReadFromLocalFile<FeatureVec>(file_path, data);
}
void ReadFromLocalFile(std::string_view file_path,
                       std::vector<uint32_t> &data) {
  return ReadFromLocalFile<std::vector<uint32_t> &>(file_path, data);
}

void WriteToLocalFile(std::string_view file_path,
                      absl::Span<const uint8_t> data) {
  std::ofstream f(std::string{file_path.data()});
  CHECK(f) << "Failed to open local file: " << file_path;
  f.write(reinterpret_cast<const char *>(data.data()),
          static_cast<int64_t>(data.size()));
  CHECK(f) << "Failed to write to local file: " << file_path;
  f.close();
}

void WriteToLocalFile(std::string_view file_path, std::string_view data) {
  static_assert(sizeof(decltype(data)::value_type) == sizeof(uint8_t));
  WriteToLocalFile(
      file_path,
      absl::Span<const uint8_t>(reinterpret_cast<const uint8_t *>(data.data()),
                                data.size()));
}

void WriteToLocalFile(std::string_view file_path, const FeatureVec &data) {
  WriteToLocalFile(
      file_path,
      absl::Span<const uint8_t>(reinterpret_cast<const uint8_t *>(data.data()),
                                sizeof(data[0]) * data.size()));
}

void WriteToLocalHashedFileInDir(std::string_view dir_path,
                                 absl::Span<const uint8_t> data) {
  if (dir_path.empty()) return;
  std::string file_path = std::filesystem::path(dir_path).append(Hash(data));
  WriteToLocalFile(file_path, data);
}

std::string HashOfFileContents(std::string_view file_path) {
  ByteArray ba;
  ReadFromLocalFile(file_path, ba);
  return Hash(ba);
}

std::string ProcessAndThreadUniqueID(std::string_view prefix) {
  // operator << is the only way to serialize std::this_thread::get_id().
  std::ostringstream oss;
  oss << prefix << getpid() << "-" << std::this_thread::get_id();
  return oss.str();
}

std::string TemporaryLocalDirPath() {
  const char *TMPDIR = getenv("TMPDIR");
  std::string tmp = TMPDIR ? TMPDIR : "/tmp";
  return std::filesystem::path(tmp).append(
      ProcessAndThreadUniqueID("centipede-"));
}

// We need to maintain a global set of dirs that CreateLocalDirRemovedAtExit()
// was called with, so that we can remove all these dirs at exit.
ABSL_CONST_INIT static absl::Mutex dirs_to_delete_at_exit_mutex{
    absl::kConstInit};
static std::vector<std::string> *dirs_to_delete_at_exit
    ABSL_GUARDED_BY(dirs_to_delete_at_exit_mutex);

// Atexit handler added by CreateLocalDirRemovedAtExit().
// Deletes all dirs in dirs_to_delete_at_exit.
static void RemoveDirsAtExit() {
  absl::MutexLock lock(&dirs_to_delete_at_exit_mutex);
  for (auto &dir : *dirs_to_delete_at_exit) {
    std::filesystem::remove_all(dir);
  }
}

void CreateLocalDirRemovedAtExit(std::string_view path) {
  // Safeguard against removing dirs not created by TemporaryLocalDirPath().
  CHECK_NE(path.find("/centipede-"), std::string::npos);
  // Create the dir.
  std::filesystem::remove_all(path);
  std::filesystem::create_directories(path);
  // Add to dirs_to_delete_at_exit.
  absl::MutexLock lock(&dirs_to_delete_at_exit_mutex);
  if (!dirs_to_delete_at_exit) {
    dirs_to_delete_at_exit = new std::vector<std::string>();
    atexit(&RemoveDirsAtExit);
  }
  dirs_to_delete_at_exit->emplace_back(path);
}

ScopedFile::ScopedFile(std::string_view dir_path, std::string_view name)
    : my_path_(std::filesystem::path(dir_path) / name) {}

ScopedFile::~ScopedFile() { std::filesystem::remove_all(my_path_); }

static const size_t kMagicLen = 11;
static const uint8_t kPackBegMagic[] = "-Centipede-";
static const uint8_t kPackEndMagic[] = "-edepitneC-";
static_assert(sizeof(kPackBegMagic) == kMagicLen + 1);
static_assert(sizeof(kPackEndMagic) == kMagicLen + 1);

// Pack 'data' such that it can be appended to a file and later extracted:
//   * kPackBegMagic
//   * hash(data)
//   * data.size() (8 bytes)
//   * data itself
//   * kPackEndMagic
// Storing the magics and the hash is a precaution against partial writes.
// UnpackBytesFromAppendFile looks for the kPackBegMagic and so
// it will ignore any partially-written data.
//
// This is simple and efficient, but I wonder if there is a ready-to-use
// standard open-source alternative. Or should we just use tar?
ByteArray PackBytesForAppendFile(const ByteArray &data) {
  ByteArray res;
  auto hash = Hash(data);
  CHECK_EQ(hash.size(), kHashLen);
  size_t size = data.size();
  uint8_t size_bytes[sizeof(size)];
  memcpy(size_bytes, &size, sizeof(size));
  res.insert(res.end(), &kPackBegMagic[0], &kPackBegMagic[kMagicLen]);
  res.insert(res.end(), hash.begin(), hash.end());
  res.insert(res.end(), &size_bytes[0], &size_bytes[sizeof(size_bytes)]);
  res.insert(res.end(), data.begin(), data.end());
  res.insert(res.end(), &kPackEndMagic[0], &kPackEndMagic[kMagicLen]);
  return res;
}

// Reverse to a sequence of PackBytesForAppendFile() appended to each other.
void UnpackBytesFromAppendFile(const ByteArray &packed_data,
                               std::vector<ByteArray> *unpacked,
                               std::vector<std::string> *hashes) {
  auto pos = packed_data.cbegin();
  while (true) {
    pos = std::search(pos, packed_data.end(), &kPackBegMagic[0],
                      &kPackBegMagic[kMagicLen]);
    if (pos == packed_data.end()) return;
    pos += kMagicLen;
    if (packed_data.end() - pos < kHashLen) return;
    std::string hash(pos, pos + kHashLen);
    pos += kHashLen;
    size_t size = 0;
    if (packed_data.end() - pos < sizeof(size)) return;
    memcpy(&size, &*pos, sizeof(size));
    pos += sizeof(size);
    if (packed_data.end() - pos < size) return;
    ByteArray ba(pos, pos + size);
    pos += size;
    if (packed_data.end() - pos < kMagicLen) return;
    if (memcmp(&*pos, kPackEndMagic, kMagicLen) != 0) continue;
    pos += kMagicLen;
    if (hash != Hash(ba)) continue;
    if (unpacked) unpacked->push_back(std::move(ba));
    if (hashes) hashes->push_back(std::move(hash));
  }
}

void AppendHashToArray(ByteArray &ba, std::string_view hash) {
  CHECK_EQ(hash.size(), kHashLen);
  ba.insert(ba.end(), hash.begin(), hash.end());
}

std::string ExtractHashFromArray(ByteArray &ba) {
  CHECK_GE(ba.size(), kHashLen);
  std::string res;
  res.insert(res.end(), ba.end() - kHashLen, ba.end());
  ba.resize(ba.size() - kHashLen);
  return res;
}

ByteArray PackFeaturesAndHash(const ByteArray &data,
                              const FeatureVec &features) {
  size_t features_len_in_bytes = features.size() * sizeof(feature_t);
  ByteArray feature_bytes_with_hash(features_len_in_bytes + kHashLen);
  memcpy(feature_bytes_with_hash.data(), features.data(),
         features_len_in_bytes);
  auto hash = Hash(data);
  CHECK_EQ(hash.size(), kHashLen);
  memcpy(feature_bytes_with_hash.data() + features_len_in_bytes, hash.data(),
         kHashLen);
  return feature_bytes_with_hash;
}

std::string UnpackFeaturesAndHash(const ByteSpan &blob, FeatureVec *features) {
  size_t features_len_in_bytes = blob.size() - kHashLen;
  features->resize(features_len_in_bytes / sizeof(feature_t));
  memcpy(features->data(), blob.data(), features_len_in_bytes);

  std::string hash;
  hash.insert(hash.end(), blob.end() - kHashLen, blob.end());
  return hash;
}

// Returns a vector of string pairs that are used to replace special characters
// and hex values in ParseAFLDictionary.
static std::vector<std::pair<std::string, std::string>>
AFLDictionaryStringReplacements() {
  std::vector<std::pair<std::string, std::string>> replacements;
  replacements.emplace_back("\\\\", "\\");
  replacements.emplace_back("\\r", "\r");
  replacements.emplace_back("\\n", "\n");
  replacements.emplace_back("\\t", "\t");
  replacements.emplace_back("\\\"", "\"");
  // Hex string replacements, lower and upper case.
  for (int i = 0; i < 256; i++) {
    replacements.emplace_back(absl::StrFormat("\\x%02x", i), std::string(1, i));
    replacements.emplace_back(absl::StrFormat("\\x%02X", i), std::string(1, i));
  }
  return replacements;
}

bool ParseAFLDictionary(std::string_view dictionary_text,
                        std::vector<ByteArray> &dictionary_entries) {
  auto replacements = AFLDictionaryStringReplacements();
  dictionary_entries.clear();
  // Check if the contents is ASCII.
  for (char ch : dictionary_text) {
    if (!std::isprint(ch) && !std::isspace(ch)) return false;
  }
  // Iterate over all lines.
  for (auto line : absl::StrSplit(dictionary_text, '\n')) {
    // [start, stop) are the offsets of the dictionary entry.
    size_t start = 0;
    // Skip leading spaces.
    while (start < line.size() && isspace(line[start])) ++start;
    // Skip empty line.
    if (start == line.size()) continue;
    // Skip comment line.
    if (line[start] == '#') continue;
    // Find the first "
    while (start < line.size() && line[start] != '"') ++start;
    if (start == line.size()) return false;  // no opening "
    ++start;                                 // skip the first "
    size_t stop = line.size() - 1;
    // Find the last "
    while (stop > start && line[stop] != '"') --stop;
    if (stop == start) return false;  // no closing "
    // Replace special characters and hex values.
    std::string replaced = absl::StrReplaceAll(
        std::string_view(line.begin() + start, stop - start), replacements);
    dictionary_entries.emplace_back(replaced.begin(), replaced.end());
  }
  return true;
}

std::vector<size_t> RandomWeightedSubset(absl::Span<const uint64_t> set,
                                         size_t target_size, Rng &rng) {
  std::vector<size_t> res;

  // Collect indices of all zeros.
  for (size_t i = 0, n = set.size(); i < n; ++i) {
    if (set[i] == 0) res.push_back(i);
  }

  // Check how many more elements need to be removed to reach `target_size`.
  if (set.size() - res.size() <= target_size) return res;
  size_t to_remove = set.size() - res.size() - target_size;

  // Pairs of index and floating point weight, ordered by weight.
  struct index_and_weight {
    size_t index;
    double weight;
    bool operator<(const index_and_weight &other) const {
      return weight < other.weight;
    }
  };

  // Similar to https://en.wikipedia.org/wiki/Reservoir_sampling#Algorithm_A-Res
  // except that we pick elements to remove from the set.
  // Invariant: queue contains up to `to_remove` smallest weights observed.
  std::priority_queue<index_and_weight> queue;
  std::uniform_real_distribution<double> unif(0, 1);  // values in [0, 1).
  for (size_t i = 0; i < set.size(); ++i) {
    auto w = set[i];
    if (w == 0) continue;
    // The idea of using rand(0,1)^(1./w) is described in the link above.
    index_and_weight iw{i, pow(unif(rng), 1. / w)};

    if (queue.size() < to_remove) {
      // queue is not full, add iw unconditionally.
      queue.push(iw);
    } else {
      // queue is full. Swap the top of queue with iw if iw is smaller.
      if (iw < queue.top()) {
        queue.pop();
        queue.push(iw);
      }
    }
  }

  // Move elements from queue to res, and sort res.
  while (!queue.empty()) {
    res.push_back(queue.top().index);
    queue.pop();
  }
  std::sort(res.begin(), res.end());
  return res;
}

namespace {
std::atomic<int> requested_exit_code = EXIT_SUCCESS;
std::atomic<bool> early_exit_requested = false;
}  // namespace

void RequestEarlyExit(int exit_code) {
  requested_exit_code = exit_code;
  early_exit_requested = true;
}

bool EarlyExitRequested() { return early_exit_requested; }

int ExitCode() { return requested_exit_code; }

uint8_t *MmapNoReserve(size_t size) {
  auto result = mmap(0, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
  CHECK(result != MAP_FAILED);
  return reinterpret_cast<uint8_t *>(result);
}

void Munmap(uint8_t *ptr, size_t size) {
  auto result = munmap(ptr, size);
  CHECK_EQ(result, 0);
}

}  // namespace centipede
