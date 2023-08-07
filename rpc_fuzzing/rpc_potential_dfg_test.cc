#include "./rpc_fuzzing/rpc_potential_dfg.h"

#include <vector>

#include "google/protobuf/descriptor.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./rpc_fuzzing/proto_field_path.h"
#include "./rpc_fuzzing/testdata/mini_blogger.pb.h"
#include "./rpc_fuzzing/testdata/mini_blogger.grpc.pb.h"

namespace fuzztest::internal {

namespace {

using ::testing::FieldsAre;
using ::testing::UnorderedElementsAre;

class RpcPotentialDfgTest : public ::testing::Test {
 protected:
  void SetUp() override {
    const google::protobuf::DescriptorPool* pool =
        google::protobuf::DescriptorPool::generated_pool();
    mini_blogger_serivce_ =
        pool->FindServiceByName("fuzztest.internal.MiniBlogger");
    ASSERT_TRUE(mini_blogger_serivce_ != nullptr);
    log_out_user_method_ =
        mini_blogger_serivce_->FindMethodByName("LogOutUser");
    ASSERT_TRUE(log_out_user_method_ != nullptr);
    log_in_user_method_ = mini_blogger_serivce_->FindMethodByName("LogInUser");
    ASSERT_TRUE(log_in_user_method_ != nullptr);
    register_user_method_ =
        mini_blogger_serivce_->FindMethodByName("RegisterUser");
    ASSERT_TRUE(register_user_method_ != nullptr);
    get_user_posts_method_ =
        mini_blogger_serivce_->FindMethodByName("GetUserPosts");
    ASSERT_TRUE(get_user_posts_method_ != nullptr);
  }
  const google::protobuf::ServiceDescriptor* mini_blogger_serivce_;
  const google::protobuf::MethodDescriptor* log_out_user_method_;
  const google::protobuf::MethodDescriptor* log_in_user_method_;
  const google::protobuf::MethodDescriptor* register_user_method_;
  const google::protobuf::MethodDescriptor* get_user_posts_method_;
};

TEST_F(RpcPotentialDfgTest,
       NodesNotDependingOnOthersHaveNoPotentialDependencies) {
  RpcPotentialDataFlowGraph dfg = CreatePotentialDfg<MiniBlogger>();

  const RpcPotentialDfgNode& register_user_node =
      dfg.GetNode(*register_user_method_);
  // RegisterUser doesn't depend on others.
  EXPECT_FALSE(register_user_node.HasDependency());

  const RpcPotentialDfgNode& log_in_user_node =
      dfg.GetNode(*log_in_user_method_);
  // LogInUser doesn't depend on others.
  EXPECT_FALSE(log_in_user_node.HasDependency());
}

TEST_F(RpcPotentialDfgTest, DependneciesSetUpBasedOnNameAndType) {
  RpcPotentialDataFlowGraph dfg = CreatePotentialDfg<MiniBlogger>();
  const RpcPotentialDfgNode& get_user_posts_node =
      dfg.GetNode(*get_user_posts_method_);
  // GetUserPostsRequest.session_id depends on LogInUserResponse.session_id.
  EXPECT_EQ(get_user_posts_node.GetAllDependencies().size(), 1);

  FieldPath get_user_posts_request_field =
      GetFieldPath<GetUserPostsRequest>("session_id");
  std::vector<RpcPotentialDfgNode::PotentialDependencySource> all_dep_sources =
      get_user_posts_node.GetDependencies(get_user_posts_request_field);

  // Depends on the session_id of the response in `LogInUser`.
  EXPECT_THAT(
      all_dep_sources,
      UnorderedElementsAre(FieldsAre(
          log_in_user_method_, GetFieldPath<LogInUserResponse>("session_id"))));
}

TEST_F(RpcPotentialDfgTest, DependneciesSetUpOnInnerFields) {
  RpcPotentialDataFlowGraph dfg = CreatePotentialDfg<MiniBlogger>();
  const RpcPotentialDfgNode& log_out_user_node =
      dfg.GetNode(*log_out_user_method_);
  // LogOutUserRequest.log_out_info.session_info.session_id and
  // LogOutUserRequest.log_out_info.session_id depends on
  // LogInUserResponse.session_id.
  EXPECT_EQ(log_out_user_node.GetAllDependencies().size(), 2);

  FieldPath log_out_user_request_field =
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id");
  std::vector<RpcPotentialDfgNode::PotentialDependencySource> all_dep_sources =
      log_out_user_node.GetDependencies(log_out_user_request_field);
  EXPECT_EQ(all_dep_sources.size(), 1);

  // Depends on the session_id of the response in `LogInUser`.
  EXPECT_THAT(
      all_dep_sources,
      UnorderedElementsAre(FieldsAre(
          log_in_user_method_, GetFieldPath<LogInUserResponse>("session_id"))));
}

}  // namespace

}  // namespace fuzztest::internal
