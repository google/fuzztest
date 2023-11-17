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

#include <cstdint>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <string>

#include "absl/flags/flag.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./centipede/blob_file.h"
#include "./centipede/config_init.h"
#include "./centipede/logging.h"
#include "./centipede/remote_file.h"
#include "./centipede/rusage_profiler.h"

ABSL_FLAG(std::string, in, "", "Input path");
ABSL_FLAG(std::string, out, "", "Output path");
ABSL_FLAG(std::string, in_format, "legacy", "--in format (legacy|riegeli)");
ABSL_FLAG(std::string, out_format, "riegeli", "--out format (legacy|riegeli)");

namespace centipede {

// TODO(ussuri): Pare down excessive rusage profiling after breaking in.

void Convert(                                             //
    const std::string& in, const std::string& in_format,  //
    const std::string& out, const std::string& out_format) {
  RPROF_THIS_FUNCTION(/*enable=*/VLOG_IS_ON(1));

  LOG(INFO) << "Converting:\n"
            << VV(in) << VV(in_format) << "\n"
            << VV(out) << VV(out_format);

  const bool in_is_riegeli = in_format == "riegeli";
  const bool out_is_riegeli = out_format == "riegeli";

  // Verify and prepare source and destination.

  CHECK(RemotePathExists(in)) << VV(in);
  RemoteMkdir(std::filesystem::path{out}.parent_path().c_str());

  // Open blob file reader and writer.

  RPROF_SNAPSHOT_AND_LOG("Opening --in");
  RPROF_START_TIMELAPSE(absl::Seconds(10), /*enable=*/VLOG_IS_ON(1));
  const auto in_reader = DefaultBlobFileReaderFactory(in_is_riegeli);
  CHECK_OK(in_reader->Open(in)) << VV(in);
  RPROF_STOP_TIMELAPSE();
  RPROF_SNAPSHOT_AND_LOG("Opened --in; opening --out");
  const auto out_writer = DefaultBlobFileWriterFactory(out_is_riegeli);
  CHECK_OK(out_writer->Open(out, "w")) << VV(out);
  RPROF_SNAPSHOT_AND_LOG("Opened --out");

  // Read and write blobs one-by-one.

  absl::Span<const uint8_t> blob;
  int num_blobs = 0;
  int num_bytes = 0;
  while (in_reader->Read(blob).ok()) {
    CHECK_OK(out_writer->Write(blob));
    ++num_blobs;
    num_bytes += blob.size();
    if (num_blobs % 100000 == 0) {
      const std::string progress =
          absl::StrCat("Done ", num_blobs, " blobs / ", num_bytes);
      LOG(INFO) << progress;
      RPROF_SNAPSHOT_AND_LOG(progress);
    }
  }
}

}  // namespace centipede

int main(int argc, char** argv) {
  (void)centipede::config::InitRuntime(argc, argv);

  const std::string in = absl::GetFlag(FLAGS_in);
  QCHECK(!in.empty());
  const std::string out = absl::GetFlag(FLAGS_out);
  QCHECK(!out.empty());
  const std::string in_format = absl::GetFlag(FLAGS_in_format);
  QCHECK(in_format == "legacy" || in_format == "riegeli") << VV(in_format);
  const std::string out_format = absl::GetFlag(FLAGS_out_format);
  QCHECK(out_format == "legacy" || out_format == "riegeli") << VV(out_format);
  QCHECK_NE(in_format, out_format);

  centipede::Convert(in, in_format, out, out_format);

  return EXIT_SUCCESS;
}
