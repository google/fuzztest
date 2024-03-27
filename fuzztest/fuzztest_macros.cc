#include "./fuzztest/fuzztest_macros.h"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

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

}  // namespace fuzztest
