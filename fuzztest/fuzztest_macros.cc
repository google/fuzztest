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
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
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
    int line_number = 0;
    for (absl::string_view line : absl::StrSplit(file.data, '\n')) {
      ++line_number;
      if (line.empty() || line[0] == '#') continue;
      auto first_index = line.find_first_of('"');
      auto last_index = line.find_last_of('"');
      CHECK(last_index != std::string::npos && first_index < last_index)
          << "Invalid dictionary entry: " << line;
      // Skip characters outside quotations.
      const absl::string_view entry =
          line.substr(first_index + 1, last_index - first_index - 1);
      absl::StatusOr<std::string> unescaped_entry =
          internal::UnescapeDictionaryEntry(entry);
      CHECK(unescaped_entry.ok())
          << unescaped_entry.status().message()
          << "; dictionary file: " << file.path << ":" << line_number;
      out.emplace_back(std::move(*unescaped_entry));
    }
  }
  return out;
}

namespace internal {
absl::StatusOr<std::string> UnescapeDictionaryEntry(absl::string_view entry) {
  // We can't use absl::CUnescape directly on the string, because it assumes hex
  // codes can have more than 2 digits, which is not the case here. "\x41BC" is
  // a valid entry that should be unescaped to "ABC", but absl::CUnescape will
  // fail as it will interpret it as a 4-digit hex code, which does not fit
  // into a single byte.
  // We unescape "\\", "\"", as well as each 2-digit hex codes (e.g. "\xab").
  std::string unescaped_entry;
  int i = 0;
  while (i < entry.size()) {
    if (entry[i] != '\\') {  // Handle unescaped character
      unescaped_entry.push_back(entry[i]);
      ++i;
    } else if (i + 1 < entry.size() &&
               (entry[i + 1] == '\\' ||
                entry[i + 1] == '"')) {  // Handle \\ and \"
      unescaped_entry.push_back(entry[i + 1]);
      i += 2;
    } else if (i + 3 < entry.size() &&
               entry[i + 1] == 'x') {  // Handle \xHH escape sequence
      std::string unescaped_hex;
      std::string error;
      if (!absl::CUnescape(entry.substr(i, 4), &unescaped_hex, &error)) {
        return absl::InvalidArgumentError(absl::StrCat(
            "Could not unescape ", entry.substr(i, 4), ": ", error));
      }
      unescaped_entry.append(unescaped_hex);
      i += 4;
    } else {  // No other escape sequences are allowed.
      return absl::InvalidArgumentError(absl::StrCat(
          "Invalid escape sequence in dictionary entry: ", entry.substr(i, 2)));
    }
  }
  return unescaped_entry;
}
}  // namespace internal

}  // namespace fuzztest
