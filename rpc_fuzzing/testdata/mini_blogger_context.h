#ifndef THIRD_PARTY_GOOGLEFUZZTEST_rpc_fuzzing_RCP_TEST_SERVER_CONTEXT_H_
#define THIRD_PARTY_GOOGLEFUZZTEST_rpc_fuzzing_RCP_TEST_SERVER_CONTEXT_H_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "./rpc_fuzzing/testdata/mini_blogger.pb.h"

namespace fuzztest::internal {

struct MiniBloggerUser {
  std::string name;
  std::string email;
  std::string passwd;
};

// The real handling logics of MiniBlogger, shared by by gRPC and other
// frameworks.
class MiniBloggerContext {
 public:
  // Adds a new user into the database.
  void RegisterUser(const RegisterUserRequest& request,
                    RegisterUserResponse& response);

  // Logs in a user if the user info exists in the database and generates a
  // session id.
  void LogInUser(const LogInUserRequest& request, LogInUserResponse& response);

  // Gets the posts for a user given the session id.
  void GetUserPosts(const GetUserPostsRequest& request,
                    GetUserPostsResponse& response);

  // Logs out a user given the session id. The session id will be invalidated.
  void LogOutUser(const LogOutUserRequest& request,
                  LogOutUserResponse& response);

 private:
  bool RegisterUserHandler(absl::string_view name, absl::string_view email,
                           absl::string_view passwd);
  std::optional<std::int64_t> LoginUserHandler(absl::string_view name,
                                               absl::string_view passwd);
  bool LogOutUserHandler(std::int64_t sid);
  std::vector<std::string> GetUserPostsHandler(std::int64_t sid);

  absl::flat_hash_map<std::string /*name*/, MiniBloggerUser> users_;
  absl::flat_hash_set<std::int64_t> active_session_ids_;
  absl::flat_hash_set<std::int64_t> inactive_session_ids_;
  absl::Mutex lock_;  // Serialize operation.
};

}  // namespace fuzztest::internal

#endif  // THIRD_PARTY_GOOGLEFUZZTEST_rpc_fuzzing_RCP_TEST_SERVER_CONTEXT_H_
