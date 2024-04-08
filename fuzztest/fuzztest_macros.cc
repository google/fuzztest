#include "./fuzztest/fuzztest_macros.h"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"

namespace fuzztest {

std::vector<std::tuple<std::string>> ReadFilesFromDirectory(
    std::string_view dir) {
  std::vector<std::tuple<std::string>> out;
  const std::filesystem::path fs_dir(dir);
  if (!std::filesystem::is_directory(fs_dir)) return out;
  for (const auto& entry :
       std::filesystem::recursive_directory_iterator(fs_dir)) {
    if (std::filesystem::is_directory(entry)) continue;
    std::ifstream stream(entry.path().string());
    if (!stream.good()) {
      // Using stderr instead of GetStderr() to avoid
      // initialization-order-fiasco when reading files at static init time with
      // `.WithSeeds(fuzztest::ReadFilesFromDirectory(...))`.
      absl::FPrintF(stderr, "[!] %s:%d: Error reading %s: (%d) %s\n", __FILE__,
                    __LINE__, entry.path().string(), errno, strerror(errno));
      continue;
    }
    std::stringstream buffer;
    buffer << stream.rdbuf();
    out.push_back({buffer.str()});
  }
  return out;
}

std::vector<std::string> ReadDictionaryFromFile(
    std::string_view dictionary_file) {
  std::vector<fuzztest::internal::FilePathAndData> files =
      fuzztest::internal::ReadFileOrDirectory(
          {dictionary_file.data(), dictionary_file.size()});

  std::vector<std::string> out;
  // Dictionary must be in the format specified at
  // https://llvm.org/docs/LibFuzzer.html#dictionaries
  for (const fuzztest::internal::FilePathAndData& file : files) {
    for (absl::string_view line : absl::StrSplit(file.data, '\n')) {
      if (line.empty() || line[0] == '#') continue;
      auto first_index = line.find_first_of('"');
      auto last_index = line.find_last_of('"');
      CHECK(last_index != std::string::npos && first_index < last_index)
          << "Invalid dictionary entry: " << line;
      // Skip characters outside quotations.
      const absl::string_view entry =
          line.substr(first_index + 1, last_index - first_index - 1);
      std::string unescaped_entry;
      CHECK(absl::CUnescape(entry, &unescaped_entry))
          << "Could not unescape: " << entry;
      out.emplace_back(std::move(unescaped_entry));
    }
  }
  return out;
}

}  // namespace fuzztest
