#include "./rpc_fuzzing/testdata/mini_blogger_context.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/random.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "./rpc_fuzzing/testdata/mini_blogger.pb.h"

namespace fuzztest::internal {

void MiniBloggerContext::RegisterUser(const RegisterUserRequest& request,
                                      RegisterUserResponse& response) {
  bool result = RegisterUserHandler(request.user_name(), request.email(),
                                    request.password());
  response.set_success(result);
}

void MiniBloggerContext::LogInUser(const LogInUserRequest& request,
                                   LogInUserResponse& response) {
  std::optional<std::int64_t> result =
      LoginUserHandler(request.name(), request.password());
  if (!result) {
    response.set_success(false);
  } else {
    response.set_success(true);
    response.set_session_id(result.value());
  }
}

void MiniBloggerContext::GetUserPosts(const GetUserPostsRequest& request,
                                      GetUserPostsResponse& response) {
  for (const std::string& post : GetUserPostsHandler(request.session_id())) {
    response.add_posts(post);
  }
}

void MiniBloggerContext::LogOutUser(const LogOutUserRequest& request,
                                    LogOutUserResponse& response) {
  if (!request.has_log_out_info() ||
      !request.log_out_info().has_session_info()) {
    response.set_success(false);
  } else {
    bool result =
        LogOutUserHandler(request.log_out_info().session_info().session_id());
    response.set_success(result);
  }
}
bool MiniBloggerContext::RegisterUserHandler(absl::string_view name,
                                             absl::string_view email,
                                             absl::string_view passwd) {
  if (name.empty() || email.empty() || passwd.empty()) return false;
  absl::WriterMutexLock l(&lock_);
  if (users_.contains(name)) return false;
  users_.emplace(std::string(name),
                 MiniBloggerUser{std::string(name), std::string(email),
                                 std::string(passwd)});
  return true;
}

std::optional<std::int64_t> MiniBloggerContext::LoginUserHandler(
    absl::string_view name, absl::string_view passwd) {
  absl::WriterMutexLock l(&lock_);
  if (!name.empty()) {
    if (!users_.contains(name)) return std::nullopt;
    if (users_[name].passwd != passwd) return std::nullopt;
  }
  absl::BitGen gen;
  std::int64_t sid =
      absl::Uniform<int64_t>(gen, 0, std::numeric_limits<int64_t>::max());
  active_session_ids_.insert(sid);
  return sid;
}

bool MiniBloggerContext::LogOutUserHandler(std::int64_t sid) {
  absl::WriterMutexLock l(&lock_);
  if (!active_session_ids_.contains(sid)) return false;
  inactive_session_ids_.insert(sid);
  active_session_ids_.erase(sid);
  return true;
}

std::vector<std::string> MiniBloggerContext::GetUserPostsHandler(
    std::int64_t sid) {
  std::vector<std::string> posts;
  absl::ReaderMutexLock l(&lock_);
  if (inactive_session_ids_.contains(sid)) {
    std::cerr << "Using an inactive session id!\n";
    std::abort();
  }
  if (active_session_ids_.contains(sid)) {
    posts.push_back("Random post");
  }
  return posts;
}

}  // namespace fuzztest::internal
