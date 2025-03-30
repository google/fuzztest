#include "./fuzztest/fuzztest_macros.h"

#include <cerrno>
#include <cstring>
#include <filesystem>  // NOLINT
#include <fstream>
#include <functional>
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
#include "./fuzztest/internal/io.h"
#include "./fuzztest/internal/logging.h"

namespace fuzztest {

namespace {
absl::StatusOr<std::string> ParseDictionaryEntry(absl::string_view entry) {
  // We can't use absl::CUnescape directly on the string, because it assumes hex
  // codes can have more than 2 digits, which is not the case here. "\x41BC" is
  // a valid entry that should be unescaped to "ABC", but absl::CUnescape will
  // fail as it will interpret it as a 4-digit hex code, which does not fit
  // into a single byte.
  // We unescape "\\", "\"", as well as each 2-digit hex codes (e.g. "\xab").
  std::string parsed_entry;
  int i = 0;
  int entry_size = (int)entry.size();
  while (i < entry_size) {
    if (entry[i] != '\\') {  // Handle unescaped character
      parsed_entry.push_back(entry[i]);
      ++i;
    } else if (i + 1 < entry_size &&
               (entry[i + 1] == '\\' ||
                entry[i + 1] == '"')) {  // Handle \\ and \"
      parsed_entry.push_back(entry[i + 1]);
      i += 2;
    } else if (i + 3 < entry_sizes &&
               entry[i + 1] == 'x') {  // Handle \xHH escape sequence
      std::string unescaped_hex;
      std::string error;
      if (!absl::CUnescape(entry.substr(i, 4), &unescaped_hex, &error)) {
        return absl::InvalidArgumentError(absl::StrCat(
            "Could not unescape ", entry.substr(i, 4), ": ", error));
      }
      if (unescaped_hex.size() != 1) {
        return absl::InvalidArgumentError(
            absl::StrCat("Could not unescape ", entry.substr(i, 4)));
      }
      parsed_entry.append(unescaped_hex);
      i += 4;
    } else {  // No other escape sequences are allowed.
      return absl::InvalidArgumentError(absl::StrCat(
          "Invalid escape sequence in dictionary entry: ", entry.substr(i, 2)));
    }
  }
  return parsed_entry;
}
}  // namespace

std::vector<std::tuple<std::string>> ReadFilesFromDirectory(
    std::string_view dir) {
  std::vector<std::tuple<std::string>> out;
  const std::filesystem::path fs_dir(dir);
  if (!std::filesystem::is_directory(fs_dir)) return out;
  for (const auto& entry :
       std::filesystem::recursive_directory_iterator(fs_dir)) {
    if (std::filesystem::is_directory(entry)) continue;
    std::ifstream stream(entry.path());
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
    out.emplace_back(std::move(buffer).str());
  }
  return out;
}

std::vector<std::tuple<std::string>> ReadFilesFromDirectory(
    std::string_view dir, std::function<bool(std::string_view)> filter) {
  std::vector<std::tuple<std::string>> out;
  const std::filesystem::path fs_dir(dir);
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(std::filesystem::is_directory(fs_dir),
                                       "Not a directory: ", fs_dir.string());
  for (const auto& entry :
       std::filesystem::recursive_directory_iterator(fs_dir)) {
    if (std::filesystem::is_directory(entry)) continue;
    if (!filter(entry.path().string())) continue;

    std::ifstream stream(entry.path());
    FUZZTEST_INTERNAL_CHECK_PRECONDITION(
        stream.good(), "Cannot read input file: ", entry.path().string(), ": ",
        strerror(errno));

    std::stringstream buffer;
    buffer << stream.rdbuf();
    out.emplace_back(std::move(buffer).str());
  }
  return out;
}

absl::StatusOr<std::vector<std::string>> ParseDictionary(
    absl::string_view text) {
  std::vector<std::string> parsed_entries;
  int line_number = 0;
  for (absl::string_view line : absl::StrSplit(text, '\n')) {
    ++line_number;

    if (line.empty() || line[0] == '#') continue;
    auto first_index = line.find_first_of('"');
    auto last_index = line.find_last_of('"');
    if (last_index == std::string::npos) {
      return absl::InvalidArgumentError(
          absl::StrCat("Unparseable dictionary entry at line ", line_number,
                       ": missing quotes"));
    }
    if (last_index <= first_index) {
      return absl::InvalidArgumentError(
          absl::StrCat("Unparseable dictionary entry at line ", line_number,
                       ": entry must be enclosed in quotes"));
    }
    // Skip characters outside quotations.
    const absl::string_view entry =
        line.substr(first_index + 1, last_index - first_index - 1);
    absl::StatusOr<std::string> parsed_entry = ParseDictionaryEntry(entry);
    if (!parsed_entry.ok()) {
      return absl::Status(
          parsed_entry.status().code(),
          absl::StrCat("Unparseable dictionary entry at line ", line_number,
                       ": ", parsed_entry.status().message()));
    }
    parsed_entries.emplace_back(std::move(*parsed_entry));
  }
  return parsed_entries;
}

std::vector<std::string> ReadDictionaryFromFile(
    std::string_view dictionary_file) {
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(
      !std::filesystem::is_directory(dictionary_file),
      "Not a file: ", dictionary_file);
  const std::filesystem::path fs_path(dictionary_file);
  std::ifstream stream(fs_path);
  CHECK(stream.good()) << "Error reading " << fs_path.string() << ": (" << errno
                       << ") " << strerror(errno);
  std::stringstream buffer;
  buffer << stream.rdbuf();
  // https://llvm.org/docs/LibFuzzer.html#dictionaries
  absl::StatusOr<std::vector<std::string>> parsed_entries =
      ParseDictionary(buffer.str());
  CHECK(parsed_entries.status().ok())
      << "Could not parse dictionary file " << fs_path << ": "
      << parsed_entries.status();
  return *parsed_entries;
}

}  // namespace fuzztest
