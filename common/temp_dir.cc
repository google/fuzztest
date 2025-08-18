#include "./common/temp_dir.h"

#include <cstdlib>
#include <filesystem>    // NOLINT
#include <system_error>  // NOLINT

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/logging.h"

namespace fuzztest::internal {

namespace fs = std::filesystem;

TempDir::TempDir(absl::string_view custom_prefix) {
  fs::path temp_root;
  temp_root = absl::NullSafeStringView(getenv("TEST_TMPDIR"));
  if (temp_root.empty()) {
    std::error_code error;
    temp_root = std::filesystem::temp_directory_path(error);
    FUZZTEST_CHECK(!error) << "Failed to get the root temp directory path: "
                           << error.message();
  }
  absl::string_view prefix = custom_prefix.empty() ? "temp_dir" : custom_prefix;
  const fs::path path_template = temp_root / absl::StrCat(prefix, "_XXXXXX");
#if !defined(_MSC_VER)
  path_ = mkdtemp(path_template.string().data());
#else
  FUZZTEST_CHECK(false) << "Windows is not supported yet.";
#endif
  FUZZTEST_CHECK(std::filesystem::is_directory(path_));
}

TempDir::~TempDir() {
  std::error_code error;
  std::filesystem::remove_all(path_, error);
  // TODO(b/432413085): Convert to FUZZTEST_CHECK once the bug is fixed.
  FUZZTEST_LOG_IF(ERROR, error) << "Unable to clean up temporary dir " << path_
                                << ": " << error.message();
}

}  // namespace fuzztest::internal
