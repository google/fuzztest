#include "./common/temp_dir.h"

#include <filesystem>    // NOLINT
#include <system_error>  // NOLINT

#include "absl/log/check.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"

namespace fuzztest::internal {

namespace fs = std::filesystem;

TempDir::TempDir(absl::string_view custom_prefix) {
  std::error_code error;
  absl::string_view prefix = custom_prefix.empty() ? "temp_dir" : custom_prefix;
  const fs::path path_template = std::filesystem::temp_directory_path(error) /
                                 absl::StrCat(prefix, "_XXXXXX");
  CHECK(!error) << "Failed to get the root temp directory path: "
                << error.message();
#if !defined(_MSC_VER)
  path_ = mkdtemp(path_template.string().data());
#else
  CHECK(false) << "Windows is not supported yet.";
#endif
  CHECK(std::filesystem::is_directory(path_));
}

TempDir::~TempDir() {
  std::error_code error;
  std::filesystem::remove_all(path_, error);
  CHECK(!error) << "Unable to clean up temporary dir " << path_ << ": "
                << error.message();
}

}  // namespace fuzztest::internal
