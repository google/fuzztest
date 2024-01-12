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

#ifndef THIRD_PARTY_CENTIPEDE_SEED_CORPUS_MAKER_LIB_H_
#define THIRD_PARTY_CENTIPEDE_SEED_CORPUS_MAKER_LIB_H_

#include <string_view>
#include <utility>
#include <vector>

#include "./centipede/defs.h"
#include "./centipede/feature.h"
#include "./centipede/seed_corpus_config.pb.h"

namespace centipede {

using CorpusElt = std::pair<ByteArray, FeatureVec>;
using InputAndFeaturesVec = std::vector<CorpusElt>;

// If a file with `config_spec` path exists, tries to parse it as a
// `SeedCorpusConfig` textproto. Otherwise, tries to parse `config_spec` as a
// verbatim `SeedCorpusConfig` textproto. Resolves any relative paths and globs
// in the config fields to absolute ones, using as the base dir either the
// file's parent dir (if `config_spec` is a file) or the current dir otherwise.
// If `override_out_dir` is non-empty, it overrides `destination.dir_path` in
// the resolved config.
SeedCorpusConfig ResolveSeedCorpusConfig(  //
    std::string_view config_spec,          //
    std::string_view override_out_dir = "");

// Extracts a sample of corpus elements from `source` and appends the results to
// `elements`. `source` defines the locations of the corpus shards and the size
// of the sample.
//
// `coverage_binary_name` should be the basename of the coverage binary for
// which the seed corpus is to be created, and the `coverage_binary_hash` should
// be the hash of that binary. If a corpus shard file found in the source
// directory contains a matching features shard file in the
// <coverage_binary_name>-<coverage_binary_hash> subdir, the matching features
// will be copied over to `elements`; otherwise, and empty `FeatureVec` will be
// used instead.
void SampleSeedCorpusElementsFromSource(    //
    const SeedCorpusSource& source,         //
    std::string_view coverage_binary_name,  //
    std::string_view coverage_binary_hash,  //
    InputAndFeaturesVec& elements);

// Writes seed corpus `elements` to `destination`. Any previously existing
// corpus shard files matching `destination.shard_glob()` will be deleted
// before writing (even if writing subsequently fails).
//
// `coverage_binary_name` should be the basename of the coverage binary for
// which the seed corpus is to be created, and the `coverage_binary_hash` should
// be the hash of that binary. The features in each `FeatureVec` of the
// `elements` will be saved to a features shard file under
// <coverage_binary_name>-<coverage_binary_hash> subdir of the destination.
void WriteSeedCorpusElementsToDestination(  //
    const InputAndFeaturesVec& elements,    //
    std::string_view coverage_binary_name,  //
    std::string_view coverage_binary_hash,  //
    const SeedCorpusDestination& destination);

// Reads and samples seed corpus elements from all the sources and writes the
// results to the destination, as defined in `config_spec`. `config_spec` can be
// either a `silifuzz.ccmp.SeedCorpusConfig` textproto file (local or remote) or
// a verbatim `silifuzz.ccmp.SeedCorpusConfig` string. The paths and globs in
// the proto can be relative paths: in that case, they are resolved to absolute
// using either the file's parent dir (if `config_spec` is a file) or the
// current dir (if `config_spec` is a verbatim string) as the base dir. If
// `override_out_dir` is non-empty, it overrides `destination.dir_path`
// specified in `config_spec`.
//
// `coverage_binary_name` should be the basename of the coverage binary for
// which the seed corpus is to be created, and the `coverage_binary_hash` should
// be the hash of that binary. The features matching each sampled source corpus
// element will be copied over from the
// <coverage_binary_name>-<coverage_binary_hash> subdir of the source to the
// same subdir of the destination.
void GenerateSeedCorpusFromConfig(          //
    std::string_view config_spec,           //
    std::string_view coverage_binary_name,  //
    std::string_view coverage_binary_hash,  //
    std::string_view override_out_dir = "");

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_SEED_CORPUS_MAKER_LIB_H_
