#include "./rpc_fuzzing/rpc_sequence.h"

#include "google/protobuf/descriptor.h"
#include "google/protobuf/util/message_differencer.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "./rpc_fuzzing/proto_field_path.h"
#include "./rpc_fuzzing/testdata/mini_blogger.pb.h"

namespace fuzztest::internal {

namespace {

using ::testing::Address;
using ::testing::ElementsAre;
using ::testing::Field;
using ::testing::Property;
using ::testing::UnorderedElementsAreArray;

TEST(RpcNodeTest, AssignOperator) {
  constexpr RpcNodeID kFromNodeId = 1;
  const google::protobuf::MethodDescriptor* method_descriptor =
      google::protobuf::DescriptorPool::generated_pool()->FindMethodByName(
          "fuzztest.internal.MiniBlogger.RegisterUser");
  CHECK(method_descriptor != nullptr);
  RpcNode node1 =
      RpcNode(*method_descriptor, std::make_unique<RegisterUserRequest>());
  node1.AddDependency(RpcDataFlowEdge{kFromNodeId});

  RpcNode node2 = node1;

  // Check that the two objects are equal.
  EXPECT_EQ(node1.method().full_name(), node2.method().full_name());
  EXPECT_TRUE(google::protobuf::util::MessageDifferencer::Equals(node1.request(),
                                                       node2.request()));
  EXPECT_THAT(node2.dependencies(),
              ElementsAre(Field(&RpcDataFlowEdge::from_node_id, kFromNodeId)));
}

TEST(RpcNodeTest, MoveAssignOperator) {
  constexpr RpcNodeID kFromNodeId = 1;
  const google::protobuf::MethodDescriptor* method_descriptor =
      google::protobuf::DescriptorPool::generated_pool()->FindMethodByName(
          "fuzztest.internal.MiniBlogger.RegisterUser");
  CHECK(method_descriptor != nullptr);
  RpcNode node1 =
      RpcNode(*method_descriptor, std::make_unique<RegisterUserRequest>());
  node1.AddDependency(RpcDataFlowEdge{kFromNodeId});

  RpcNode clone = node1;
  RpcNode node2 = std::move(clone);

  // Check that the two objects are equal.
  EXPECT_EQ(node1.method().full_name(), node2.method().full_name());
  EXPECT_TRUE(google::protobuf::util::MessageDifferencer::Equals(node1.request(),
                                                       node2.request()));
  EXPECT_THAT(node2.dependencies(),
              ElementsAre(Field(&RpcDataFlowEdge::from_node_id, kFromNodeId)));
}

TEST(RpcNodeTest, CopyConstructor) {
  constexpr RpcNodeID kFromNodeId = 1;
  const google::protobuf::MethodDescriptor* method_descriptor =
      google::protobuf::DescriptorPool::generated_pool()->FindMethodByName(
          "fuzztest.internal.MiniBlogger.RegisterUser");
  CHECK(method_descriptor != nullptr);
  RpcNode node1 =
      RpcNode(*method_descriptor, std::make_unique<RegisterUserRequest>());
  node1.AddDependency(RpcDataFlowEdge{kFromNodeId});

  RpcNode node2(node1);

  // Check that the two objects are equal.
  EXPECT_EQ(node1.method().full_name(), node2.method().full_name());
  EXPECT_TRUE(google::protobuf::util::MessageDifferencer::Equals(node1.request(),
                                                       node2.request()));
  EXPECT_THAT(node2.dependencies(),
              ElementsAre(Field(&RpcDataFlowEdge::from_node_id, kFromNodeId)));
}

TEST(RpcNodeTest, EqualityTest) {
  constexpr RpcNodeID kFromNodeId = 1;
  const google::protobuf::MethodDescriptor* method_descriptor =
      google::protobuf::DescriptorPool::generated_pool()->FindMethodByName(
          "fuzztest.internal.MiniBlogger.RegisterUser");
  ASSERT_NE(method_descriptor, nullptr);
  RpcNode node1 =
      RpcNode(*method_descriptor, std::make_unique<RegisterUserRequest>());
  node1.AddDependency(RpcDataFlowEdge{kFromNodeId});

  RpcNode node2(node1);

  EXPECT_EQ(node1, node2);
}

TEST(RpcNodeTest, InEqualityTest) {
  constexpr RpcNodeID kFromNodeId = 1;
  const google::protobuf::MethodDescriptor* method_descriptor =
      google::protobuf::DescriptorPool::generated_pool()->FindMethodByName(
          "fuzztest.internal.MiniBlogger.RegisterUser");
  ASSERT_NE(method_descriptor, nullptr);
  RpcNode node1 =
      RpcNode(*method_descriptor, std::make_unique<RegisterUserRequest>());
  node1.AddDependency(RpcDataFlowEdge{kFromNodeId});

  RpcNode node2 =
      RpcNode(*method_descriptor, std::make_unique<RegisterUserRequest>());

  EXPECT_NE(node1, node2);
}

TEST(RpcDataFlowEdgeTest, EqualityTest) {
  RpcDataFlowEdge edge1 =
      RpcDataFlowEdge{0, GetFieldPath<LogInUserResponse>("session_id"),
                      GetFieldPath<GetUserPostsRequest>("session_id")};
  RpcDataFlowEdge edge2 =
      RpcDataFlowEdge{0, GetFieldPath<LogInUserResponse>("session_id"),
                      GetFieldPath<GetUserPostsRequest>("session_id")};

  EXPECT_EQ(edge1, edge2);
}

TEST(RpcDataFlowEdgeTest, InEqualityTest) {
  RpcDataFlowEdge edge1 =
      RpcDataFlowEdge{0, GetFieldPath<LogInUserResponse>("session_id"),
                      GetFieldPath<GetUserPostsRequest>("session_id")};
  RpcDataFlowEdge edge2 = RpcDataFlowEdge{
      0, GetFieldPath<LogInUserResponse>("session_id"),
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id")};

  EXPECT_NE(edge1, edge2);
}

class RpcDataFlowGraphTest : public ::testing::Test {
 protected:
  void SetUp() override {
    log_in_user_method_ =
        google::protobuf::DescriptorPool::generated_pool()->FindMethodByName(
            "fuzztest.internal.MiniBlogger.LogInUser");
    log_out_user_method_ =
        google::protobuf::DescriptorPool::generated_pool()->FindMethodByName(
            "fuzztest.internal.MiniBlogger.LogOutUser");
    register_user_method_ =
        google::protobuf::DescriptorPool::generated_pool()->FindMethodByName(
            "fuzztest.internal.MiniBlogger.RegisterUser");
  }

  RpcNode CreateLogInUserNode(RpcNodeID log_in_node_id) {
    return RpcNode(*log_in_user_method_, std::make_unique<LogInUserRequest>());
  }

  RpcNode CreateRegisterUserNode(RpcNodeID log_out_node_id) {
    return RpcNode(*register_user_method_,
                   std::make_unique<RegisterUserRequest>());
  }

  std::pair<RpcNode, RpcNode> CreateLogInOutUserNodePairWithDep(
      RpcNodeID log_in_node_id) {
    // Set up a node for LogInUser and LogOutUser. Establish a dependency from
    // LogInUserResponse.session_id to
    // LogOutUserRequest.log_out_info.session_info.session_id.
    RpcNode log_in_user_node(*log_in_user_method_,
                             std::make_unique<LogInUserResponse>());
    RpcNode log_out_user_node(*log_out_user_method_,
                              std::make_unique<LogOutUserRequest>());
    log_out_user_node.AddDependency(RpcDataFlowEdge{
        log_in_node_id, GetFieldPath<LogInUserResponse>("session_id"),
        GetFieldPath<LogOutUserRequest>(
            "log_out_info.session_info.session_id")});
    return std::make_pair(log_in_user_node, log_out_user_node);
  }

  const google::protobuf::MethodDescriptor *log_in_user_method_, *log_out_user_method_,
      *register_user_method_;
  RpcNodeID log_in_node_id_ = 0x123;
  RpcNodeID log_out_node_id_ = 0x234;
};

TEST_F(RpcDataFlowGraphTest, GetSequenceReturnTologicalSortedSequence) {
  RpcDataFlowGraph graph;
  auto [log_in_user_node, log_out_user_node] =
      CreateLogInOutUserNodePairWithDep(log_in_node_id_);
  // Add LogOutUser first, so that the topological sort should change its order.
  graph.AddNode(log_out_node_id_, log_out_user_node);
  graph.AddNode(log_in_node_id_, log_in_user_node);

  RpcSequence sequence = graph.GetSequence();
  EXPECT_THAT(
      sequence,
      ElementsAre(Property(&RpcNode::method, Address(log_in_user_method_)),
                  Property(&RpcNode::method, Address(log_out_user_method_))));
}

TEST_F(RpcDataFlowGraphTest, GetSequenceReMapAllTheRpcNodeIdToSequenceIndex) {
  auto [log_in_user_node, log_out_user_node] =
      CreateLogInOutUserNodePairWithDep(log_in_node_id_);
  RpcDataFlowGraph graph;
  graph.AddNode(log_in_node_id_, log_in_user_node);
  graph.AddNode(log_out_node_id_, log_out_user_node);

  RpcSequence sequence = graph.GetSequence();
  EXPECT_EQ(&sequence[1].method(), log_out_user_method_);
  EXPECT_THAT(sequence[1].dependencies(),
              ElementsAre(Field(&RpcDataFlowEdge::from_node_id,
                                0 /* remap `kNode1Id` to 0*/)));
}

TEST_F(RpcDataFlowGraphTest, GetSequenceReturnRandomizedTopoSortedSequence) {
  const std::string_view expected_methods_of_first_nodes[] = {"LogInUser",
                                                              "RegisterUser"};
  absl::flat_hash_set<std::string> methods_of_first_nodes;
  for (int i = 0; i < 100; ++i) {
    RpcDataFlowGraph graph;
    graph.AddNode(0, CreateLogInUserNode(log_in_node_id_));
    graph.AddNode(1, CreateRegisterUserNode(log_out_node_id_));
    methods_of_first_nodes.insert(graph.GetSequence()[0].method().name());
  }

  EXPECT_THAT(methods_of_first_nodes,
              UnorderedElementsAreArray(expected_methods_of_first_nodes));
}

TEST_F(RpcDataFlowGraphTest, FromSequenceRecoversNodesAndOrdering) {
  RpcSequence sequence = {CreateLogInUserNode(log_in_node_id_),
                          CreateRegisterUserNode(log_out_node_id_)};
  RpcDataFlowGraph graph = RpcDataFlowGraph::FromSequence(sequence);
  EXPECT_EQ(graph.GetSequence(), sequence);
}

TEST_F(RpcDataFlowGraphTest,
       GetSequenceReturnTheSameRandomizedTopoSortedSequence) {
  RpcDataFlowGraph graph;
  graph.AddNode(0, CreateLogInUserNode(log_in_node_id_));
  graph.AddNode(1, CreateRegisterUserNode(log_out_node_id_));
  absl::string_view method_name = graph.GetSequence()[0].method().name();
  for (int i = 0; i < 100; ++i) {
    EXPECT_EQ(method_name, graph.GetSequence()[0].method().name());
  }
}

TEST_F(
    RpcDataFlowGraphTest,
    GetSequenceReturnDifferentRandomizedTopoSortedSequenceAfterModification) {
  const std::string_view expected_methods_of_first_nodes[] = {"LogInUser",
                                                              "RegisterUser"};
  absl::flat_hash_set<std::string> methods_of_first_nodes;
  RpcDataFlowGraph graph;
  graph.AddNode(0, CreateLogInUserNode(log_in_node_id_));
  graph.AddNode(1, CreateRegisterUserNode(log_out_node_id_));
  for (int i = 0; i < 100; ++i) {
    graph.RemoveNode(1);
    graph.AddNode(1, CreateRegisterUserNode(log_out_node_id_));
    methods_of_first_nodes.insert(graph.GetSequence()[0].method().name());
  }
  EXPECT_THAT(methods_of_first_nodes,
              UnorderedElementsAreArray(expected_methods_of_first_nodes));
}

TEST_F(RpcDataFlowGraphTest,
       GetRandomSequenceAlwaysReturnRandomizedTopoSortedSequence) {
  const std::string_view expected_methods_of_first_nodes[] = {"LogInUser",
                                                              "RegisterUser"};
  absl::flat_hash_set<std::string> methods_of_first_nodes;
  RpcDataFlowGraph graph;
  graph.AddNode(0, CreateLogInUserNode(log_in_node_id_));
  graph.AddNode(1, CreateRegisterUserNode(log_out_node_id_));
  for (int i = 0; i < 100; ++i) {
    graph.RandomizeTopologicalOrdering();
    methods_of_first_nodes.insert(graph.GetSequence()[0].method().name());
  }

  EXPECT_THAT(methods_of_first_nodes,
              UnorderedElementsAreArray(expected_methods_of_first_nodes));
}

}  // namespace

}  // namespace fuzztest::internal
