#include "./fuzztest/internal/domains/utf.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"

namespace fuzztest {

std::string EncodeAsUTF8(const std::vector<int>& code_points) {
  std::string out;
  out.reserve(code_points.size());
  for (int c : code_points) {
    if ((static_cast<uint32_t>(c) < 0xD800) || (c >= 0xE000 && c <= 0x10FFFF)) {
      char buf[4];
      out.append(std::string(buf, runetochar(buf, &c)));
    } else {
      static constexpr char ReplacementChars[] = {'\xEF', '\xBF', '\xBD'};
      out.append(ReplacementChars, sizeof(ReplacementChars));
    }
  }
  return out;
}

std::optional<std::vector<int>> DecodeFromUTF8(const std::string& utf8) {
  std::vector<int> out;
  absl::string_view in(utf8);
  out.reserve(in.size());
  while (!in.empty()) {
    Rune r;
    int len = chartorune(&r, in.data());
    out.push_back(r);
    if (r == Runeerror && len != 3) return std::nullopt;
    in.remove_prefix(len);
  }
  return out;
}

}  // namespace fuzztest
