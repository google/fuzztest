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

// The Centipede seed corpus maker. Following the input text proto config in the
// ./seed_corpus_config.proto format, selects a sample of fuzzing inputs from N
// Centipede workdirs and writes them out to a new set of Centipede corpus file
// shards.

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <functional>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_replace.h"
#include "absl/types/span.h"
#include "./centipede/blob_file.h"
#include "./centipede/defs.h"
#include "./centipede/logging.h"
#include "./centipede/remote_file.h"
#include "./centipede/seed_corpus_config.pb.h"
#include "google/protobuf/text_format.h"

// TODO(ussuri): Add unit tests.
// TODO(ussuri): Parallelize I/O where possible.
// TODO(ussuri): Implement a smarter on-the-fly sampling to avoid having to
//  load all of a source's elements into RAM only to pick some of them. That
//  would be trivial if the number of elements in a corpus file could be
//  determined without reading all of it.
// TODO(ussuri): Switch from hard CHECKs to returning absl::Status once
//  convenience macros are available (RETURN_IF_ERROR etc.).

namespace centipede {

namespace fs = std::filesystem;

SeedCorpusConfig ResolveSeedCorpusConfig(  //
    std::string_view config_spec,          //
    std::string_view override_out_dir) {
  std::string config_str;
  std::string base_dir;

  CHECK(!config_spec.empty());

  if (RemotePathExists(config_spec)) {
    LOG(INFO) << "Config spec points at an existing file; trying to parse "
                 "textproto config from it: "
              << VV(config_spec);
    RemoteFileGetContents(config_spec, config_str);
    LOG(INFO) << "Raw config read from file:\n" << config_str;
    base_dir = std::filesystem::path{config_spec}.parent_path();
  } else {
    LOG(INFO) << "Config spec is not a file, or file doesn't exist; trying to "
                 "parse textproto config verbatim: "
              << VV(config_spec);
    config_str = config_spec;
    base_dir = fs::current_path();
  }

  SeedCorpusConfig config;
  CHECK(google::protobuf::TextFormat::ParseFromString(config_str, &config))
      << "Couldn't parse config: " << VV(config_str);
  CHECK_EQ(config.sources_size() > 0, config.has_destination())
      << "Non-empty config must have both source(s) and destination: "
      << VV(config_spec) << VV(config.DebugString());

  LOG(INFO) << "Parsed config:\n" << config.DebugString();

  // Resolve relative `source.dir_glob`s in the config to absolute ones.
  for (auto& src : *config.mutable_sources()) {
    auto* dir = src.mutable_dir_glob();
    if (dir->empty() || !fs::path{*dir}.is_absolute()) {
      *dir = fs::path{base_dir} / *dir;
    }
  }

  // Set `destination.dir_path` to `override_out_dir`, if the latter is
  // non-empty, or resolve a relative `destination.dir_path` to an absolute one.
  if (config.has_destination()) {
    auto* dir = config.mutable_destination()->mutable_dir_path();
    if (!override_out_dir.empty()) {
      *dir = override_out_dir;
    } else if (dir->empty() || !fs::path{*dir}.is_absolute()) {
      *dir = fs::path{base_dir} / *dir;
    }
  }

  LOG(INFO) << "Resolved config:\n" << config.DebugString();

  return config;
}

void SampleSeedCorpusElementsFromSource(  //
    const SeedCorpusSource& source,       //
    std::vector<centipede::ByteArray>& elements) {
  LOG(INFO) << "Reading/sampling seed corpus elements from source:\n"
            << source.DebugString();

  // Find `source.dir_blog()`-matching dirs and pick at most
  // `source.num_recent_dirs()` most recent ones.

  std::vector<std::string> corpus_dirs;
  RemoteGlobMatch(source.dir_glob(), corpus_dirs);
  LOG(INFO) << "Found " << corpus_dirs.size() << " corpus dirs matching "
            << source.dir_glob();
  // Sort in the ascending lexicographical order. We expect that dir names
  // contain timestamps and therefore will be sorted from oldest to newest.
  std::sort(corpus_dirs.begin(), corpus_dirs.end(), std::less<std::string>());
  if (source.num_recent_dirs() < corpus_dirs.size()) {
    corpus_dirs.erase(  //
        corpus_dirs.begin(), corpus_dirs.end() - source.num_recent_dirs());
    LOG(INFO) << "Selected " << corpus_dirs.size() << " corpus dirs";
  }

  // Find all the corpus shard files in the found dirs.

  std::vector<std::string> shard_fnames;
  for (const auto& dir : corpus_dirs) {
    const std::string shards_glob = fs::path{dir} / source.shard_rel_glob();
    // NOTE: `RemoteGlobMatch` appends to the output list.
    const auto prev_num_shards = shard_fnames.size();
    RemoteGlobMatch(shards_glob, shard_fnames);
    LOG(INFO) << "Found " << (shard_fnames.size() - prev_num_shards)
              << " shards matching " << shards_glob;
  }
  LOG(INFO) << "Found " << shard_fnames.size() << " shards total in source "
            << source.dir_glob();

  if (shard_fnames.empty()) {
    LOG(WARNING) << "Skipping empty source " << source.dir_glob();
    return;
  }

  // Read all the elements from the found corpus shard files.

  std::vector<centipede::ByteArray> src_elts;

  for (const auto& shard_fname : shard_fnames) {
    std::unique_ptr<centipede::BlobFileReader> corpus_reader =
        centipede::DefaultBlobFileReaderFactory();
    CHECK(corpus_reader != nullptr);
    CHECK_OK(corpus_reader->Open(shard_fname)) << VV(shard_fname);

    absl::Status read_status;
    size_t num_read_elts = 0;
    while (true) {
      absl::Span<uint8_t> elt;
      read_status = corpus_reader->Read(elt);
      // Reached EOF - done with this shard.
      if (absl::IsOutOfRange(read_status)) break;
      CHECK_OK(read_status)
          << "Failure reading elements from shard " << shard_fname;
      // TODO(b/302558385): Replace with a CHECK.
      LOG_IF(ERROR, elt.empty()) << "Read empty element: " << VV(shard_fname);
      src_elts.emplace_back(elt.begin(), elt.end());
      ++num_read_elts;
    }

    corpus_reader->Close().IgnoreError();

    LOG(INFO) << "Read " << num_read_elts << " elements from shard "
              << shard_fname;
  }

  LOG(INFO) << "Read " << src_elts.size() << " elements total from source "
            << source.dir_glob();

  // Extract a sample of the elements of the size specified in
  // `source.sample_size()`.

  size_t sample_size = 0;
  switch (source.sample_size_case()) {
    case SeedCorpusSource::kSampledFraction:
      CHECK(source.sampled_fraction() > 0.0 && source.sampled_fraction() <= 1.0)
          << VV(source.DebugString());
      sample_size = std::llrint(src_elts.size() * source.sampled_fraction());
      break;
    case SeedCorpusSource::kSampledCount:
      sample_size = std::min<size_t>(src_elts.size(), source.sampled_count());
      break;
    case SeedCorpusSource::SAMPLE_SIZE_NOT_SET:
      sample_size = src_elts.size();
      break;
  }

  if (sample_size < src_elts.size()) {
    LOG(INFO) << "Sampling " << sample_size << " elements out of "
              << src_elts.size();
    std::sample(  //
        src_elts.cbegin(), src_elts.cend(), std::back_inserter(elements),
        sample_size, absl::BitGen{});
  } else {
    LOG(INFO) << "Using all " << src_elts.size() << " elements";
    // TODO(ussuri): Should we still use std::sample() to randomize the order?
    elements.insert(elements.end(), src_elts.cbegin(), src_elts.cend());
  }
}

void WriteSeedCorpusElementsToDestination(              //
    const std::vector<centipede::ByteArray>& elements,  //
    const SeedCorpusDestination& destination) {
  LOG(INFO) << "Writing seed corpus elements to destination:\n"
            << destination.DebugString();

  CHECK_GT(destination.num_shards(), 0)
      << "Requested number of shards can't be 0";
  CHECK(absl::StrContains(destination.shard_rel_glob(), "*"))
      << "Shard pattern must contain '*' placeholder for shard index";

  // Compute shard sizes. If the elements can't be evenly divided between the
  // requested number of shards, distribute the N excess elements between the
  // first N shards.
  const size_t shard_size = elements.size() / destination.num_shards();
  std::vector<size_t> shard_sizes(destination.num_shards(), shard_size);
  const size_t excess_elts = elements.size() % destination.num_shards();
  for (size_t i = 0; i < excess_elts; ++i) {
    ++shard_sizes[i];
  }

  // Write the elements to the shard files.
  // TODO(b/295978603): Replace the 6 with `WorkdirMgr::kDigitsInShardIndex`.
  const auto shard_index_digits = destination.shard_index_digits() > 0
                                      ? destination.shard_index_digits()
                                      : 6;
  auto elt_it = elements.cbegin();
  for (size_t s = 0; s < shard_sizes.size(); ++s) {
    // Generate the output shard's filename.
    const std::string shard_idx =
        absl::StrFormat("%0*d", shard_index_digits, s);
    const std::string shard_rel_fname =
        absl::StrReplaceAll(destination.shard_rel_glob(), {{"*", shard_idx}});
    const std::string shard_fname =
        fs::path{destination.dir_path()} / shard_rel_fname;

    LOG(INFO) << "Writing " << shard_sizes[s] << " elements to " << shard_fname;

    // Open the shard's file.
    std::unique_ptr<centipede::BlobFileWriter> corpus_writer =
        centipede::DefaultBlobFileWriterFactory();
    CHECK(corpus_writer != nullptr);
    CHECK_OK(corpus_writer->Open(shard_fname, "w")) << VV(shard_fname);

    // Write the shard's elements to the file.
    for (size_t e = 0, ee = shard_sizes[s]; e < ee; ++e) {
      CHECK(elt_it != elements.cend());
      CHECK_OK(corpus_writer->Write(*elt_it)) << VV(shard_fname);
      ++elt_it;
    }

    CHECK_OK(corpus_writer->Close()) << VV(shard_fname);
  }
}

void GenerateSeedCorpusFromConfig(  //
    std::string_view config_spec,   //
    std::string_view override_out_dir) {
  const SeedCorpusConfig config =
      ResolveSeedCorpusConfig(config_spec, override_out_dir);

  if (config.sources_size() == 0 || !config.has_destination()) {
    LOG(WARNING) << "Config is empty: skipping seed corpus generation";
    return;
  }

  // Pre-create the destination dir early to catch possible misspellings etc.
  RemoteMkdir(config.destination().dir_path());

  std::vector<centipede::ByteArray> elements;
  for (const auto& source : config.sources()) {
    SampleSeedCorpusElementsFromSource(source, elements);
  }
  LOG(INFO) << "Sampled " << elements.size() << " elements from "
            << config.sources_size() << " seed corpus source(s)";

  WriteSeedCorpusElementsToDestination(elements, config.destination());
  LOG(INFO) << "Wrote " << elements.size()
            << " elements to seed corpus destination";
}

}  // namespace centipede
