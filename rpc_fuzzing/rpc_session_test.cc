#include "./rpc_fuzzing/rpc_session.h"

#include <cstdint>
#include <optional>
#include <variant>

#include "google/protobuf/descriptor.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/random/random.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/serialization.h"
#include "./rpc_fuzzing/proto_field_path.h"
#include "./rpc_fuzzing/rpc_potential_dfg.h"
#include "./rpc_fuzzing/rpc_sequence.h"
#include "./rpc_fuzzing/testdata/mini_blogger.pb.h"
#include "./rpc_fuzzing/testdata/mini_blogger.grpc.pb.h"

namespace fuzztest::internal {

namespace {

using ::testing::AnyOf;
using ::testing::Conditional;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::FieldsAre;
using ::testing::IsTrue;
using ::testing::NanSensitiveDoubleEq;
using ::testing::Optional;
using ::testing::Pair;
using ::testing::ResultOf;
using ::testing::UnorderedElementsAre;
using ::testing::UnorderedElementsAreArray;
using ::testing::VariantWith;

template <typename T>
auto ValueIs(const T& v) {
  if constexpr (std::is_same_v<T, double>) {
    return FieldsAre(VariantWith<double>(NanSensitiveDoubleEq(v)));
  } else {
    return FieldsAre(VariantWith<T>(v));
  }
}

template <typename... T>
auto SubsAre(const T&... v) {
  return FieldsAre(VariantWith<std::vector<IRObject>>(ElementsAre(v...)));
}

class RpcDomainTest : public ::testing::Test {
 public:
  RpcDomainTest()
      : pool_(*ABSL_DIE_IF_NULL(google::protobuf::DescriptorPool::generated_pool())),
        mini_blogger_serivce_(*ABSL_DIE_IF_NULL(
            pool_.FindServiceByName("fuzztest.internal.MiniBlogger"))),
        log_in_user_method_(*ABSL_DIE_IF_NULL(
            mini_blogger_serivce_.FindMethodByName("LogInUser"))),
        log_out_user_method_(*ABSL_DIE_IF_NULL(
            mini_blogger_serivce_.FindMethodByName("LogOutUser"))),
        get_user_posts_method_(*ABSL_DIE_IF_NULL(
            mini_blogger_serivce_.FindMethodByName("GetUserPosts"))) {}

 protected:
  RpcNode GetLogInUserNode() const {
    return RpcNode(log_in_user_method_, std::make_unique<LogInUserRequest>());
  }

  RpcNode GetLogOutUserNode() const {
    return RpcNode(log_out_user_method_, std::make_unique<LogOutUserRequest>());
  }

  RpcNode GetGetUserPostsNode() const {
    return RpcNode(get_user_posts_method_,
                   std::make_unique<GetUserPostsRequest>());
  }

  RpcDataFlowGraph CreateRandomGraph(RpcSessionImpl<MiniBlogger>& rpc_domain) {
    absl::BitGen gen;
    RpcDataFlowGraph graph = rpc_domain.Init(gen);
    for (int i = 0; i < 100; ++i) {
      rpc_domain.Mutate(graph, gen, false);
    }
    // Generate an order.
    (void)graph.GetOrderedNodeIds();
    return graph;
  }

  const google::protobuf::DescriptorPool& pool_;
  const google::protobuf::ServiceDescriptor& mini_blogger_serivce_;
  const google::protobuf::MethodDescriptor& log_in_user_method_;
  const google::protobuf::MethodDescriptor& log_out_user_method_;
  const google::protobuf::MethodDescriptor& get_user_posts_method_;
};

TEST_F(RpcDomainTest, InitGeneratesARandomSingleCallWithoutDependencies) {
  RpcSessionImpl<MiniBlogger> rpc_domain;
  absl::BitGen bitgen;
  for (int i = 0; i < 100; ++i) {
    RpcDataFlowGraph value = rpc_domain.Init(bitgen);
    EXPECT_THAT(value.GetAllNodes(),
                ElementsAre(Pair(0, ResultOf(
                                        [](const RpcNode& node) {
                                          return node.dependencies().empty();
                                        },
                                        IsTrue()))));
  }
}

TEST_F(RpcDomainTest, MutationOnlyInsertsNodesThatDependOnExistingNodes) {
  constexpr std::string_view kMethodsDependingLogInUser[] = {"GetUserPosts",
                                                             "LogOutUser"};

  RpcDataFlowGraph graph;
  graph.AddNode(0, GetLogInUserNode());
  absl::flat_hash_set<std::string> inserted_methods;
  RpcSessionImpl<MiniBlogger> rpc_domain;
  absl::BitGen bitgen;
  for (int j = 0; j < 100; ++j) {
    RpcDataFlowGraph mutated_graph = graph;
    rpc_domain.Mutate(mutated_graph, bitgen, false);
    if (mutated_graph.NodeNum() != 2) continue;
    // Mutated through insertion.
    inserted_methods.insert(mutated_graph.GetSequence()[1].method().name());
  }
  EXPECT_THAT(inserted_methods,
              UnorderedElementsAreArray(kMethodsDependingLogInUser));
}

TEST_F(RpcDomainTest, InsertedNodesHaveDependenciesOnExistingNodes) {
  constexpr RpcNodeID kFromNodeID = 0;
  RpcDataFlowGraph graph;
  graph.AddNode(kFromNodeID, GetLogInUserNode());

  bool insertion_triggerred = false;
  RpcSessionImpl<MiniBlogger> rpc_domain;
  absl::BitGen bitgen;
  for (int j = 0; j < 100; ++j) {
    RpcDataFlowGraph mutated_graph = graph;
    rpc_domain.Mutate(mutated_graph, bitgen, false);
    if (mutated_graph.NodeNum() != 2) continue;
    // Mutated through insertion.
    insertion_triggerred = true;

    const RpcNode inserted_node = mutated_graph.GetSequence()[1];
    EXPECT_THAT(
        inserted_node.dependencies(),
        ElementsAre(FieldsAre(
            kFromNodeID, GetFieldPath<LogInUserResponse>("session_id"),
            Conditional(inserted_node.method().name() == "LogOutUser",
                        AnyOf(GetFieldPath<LogOutUserRequest>(
                                  "log_out_info.session_info.session_id"),
                              GetFieldPath<LogOutUserRequest>(
                                  "log_out_info.session_id")),
                        GetFieldPath<GetUserPostsRequest>("session_id")))));
  }

  EXPECT_TRUE(insertion_triggerred);
}

TEST_F(RpcDomainTest, InsertedNodeSelectsRandomAlternativeDepWithinSameOneOf) {
  constexpr RpcNodeID kFromNodeID = 0;
  RpcDataFlowGraph graph;
  graph.AddNode(kFromNodeID, GetLogInUserNode());

  RpcSessionImpl<MiniBlogger> rpc_domain;
  absl::flat_hash_set<std::string> sink_fields;
  absl::BitGen bitgen;
  for (int j = 0; j < 200; ++j) {
    RpcDataFlowGraph mutated_graph = graph;
    rpc_domain.Mutate(mutated_graph, bitgen, false);
    if (mutated_graph.NodeNum() != 2 ||
        mutated_graph.GetSequence()[1].method().name() != "LogOutUser")
      continue;
    // Either `log_out_info.session_info.session_id` or
    // `log_out_info.session_id` will be selected as the sink.
    EXPECT_EQ(mutated_graph.GetSequence()[1].dependencies().size(), 1);
    sink_fields.insert(
        mutated_graph.GetSequence()[1].dependencies()[0].to_field.ToString());
  }
  EXPECT_THAT(sink_fields,
              UnorderedElementsAre("log_out_info.session_info.session_id",
                                   "log_out_info.session_id"));
}

TEST_F(RpcDomainTest, MutationOnlyDeletesTailNodes) {
  constexpr std::string_view kMethodsDependingLogInUser[] = {"GetUserPosts",
                                                             "LogOutUser"};
  // Node id 0.
  RpcNode log_in_user_node = GetLogInUserNode();
  // Node id 1.
  RpcNode log_out_user_node = GetLogOutUserNode();
  // Node id 2.
  RpcNode get_user_posts_node = GetGetUserPostsNode();

  log_out_user_node.AddDependency(RpcDataFlowEdge{
      0, GetFieldPath<LogInUserResponse>("session_id"),
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id")});

  get_user_posts_node.AddDependency(
      RpcDataFlowEdge{0, GetFieldPath<LogInUserResponse>("session_id"),
                      GetFieldPath<GetUserPostsRequest>("session_id")});

  RpcDataFlowGraph graph;
  graph.AddNode(0, log_in_user_node);
  graph.AddNode(1, log_out_user_node);
  graph.AddNode(2, get_user_posts_node);

  absl::flat_hash_set<std::string> deleted_methods;
  RpcSessionImpl<MiniBlogger> rpc_domain;
  absl::BitGen bitgen;

  for (int j = 0; j < 100; ++j) {
    RpcDataFlowGraph mutated_graph = graph;
    rpc_domain.Mutate(mutated_graph, bitgen, false);
    if (mutated_graph.NodeNum() != 2) continue;
    // Mutated through deletion.
    if (mutated_graph.GetSequence()[1].method().name() == "LogOutUser") {
      deleted_methods.insert("GetUserPosts");
    } else {
      deleted_methods.insert("LogOutUser");
    }
  }
  EXPECT_THAT(deleted_methods,
              UnorderedElementsAreArray(kMethodsDependingLogInUser));
}

TEST_F(RpcDomainTest, OnlyShrinkMutationDecreasesNodeNumOrRequest) {
  RpcNode log_in_user_node = GetLogInUserNode();
  auto get_user_post_request = std::make_unique<GetUserPostsRequest>();
  get_user_post_request->set_max_posts(100);
  RpcNode log_out_user_node(get_user_posts_method_,
                            std::move(get_user_post_request));
  log_out_user_node.AddDependency(RpcDataFlowEdge{
      0, GetFieldPath<LogInUserResponse>("session_id"),
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id")});

  RpcDataFlowGraph graph;
  graph.AddNode(0, log_in_user_node);
  graph.AddNode(1, log_out_user_node);

  RpcSessionImpl<MiniBlogger> rpc_domain;
  absl::BitGen bitgen;
  bool static_field_shrinked = false;
  for (int i = 0; i < 100; ++i) {
    RpcDataFlowGraph mutated_graph = graph;
    rpc_domain.Mutate(mutated_graph, bitgen, true);

    if (mutated_graph.NodeNum() == 2) {
      const RpcNode& node = mutated_graph.GetNode(1);
      int new_max_posts = node.request().GetReflection()->GetInt32(
          node.request(),
          node.request().GetDescriptor()->FindFieldByName("max_posts"));
      EXPECT_LE(new_max_posts, 100);
      if (new_max_posts < 100) {
        static_field_shrinked = true;
      }
    } else {
      EXPECT_EQ(mutated_graph.NodeNum(), 1);
    }
  }
  EXPECT_TRUE(static_field_shrinked);
}

TEST_F(RpcDomainTest, MutateEventuallyChangesStaticFieldInRequest) {
  RpcDataFlowGraph graph;
  graph.AddNode(0, GetLogInUserNode());

  RpcSessionImpl<MiniBlogger> rpc_domain;
  absl::BitGen bitgen;
  bool static_field_changed = false;
  for (int i = 0; i < 100; ++i) {
    RpcDataFlowGraph mutated_graph = graph;
    rpc_domain.Mutate(mutated_graph, bitgen, false);
    if (mutated_graph.NodeNum() == graph.NodeNum() &&
        mutated_graph.GetNode(0).method().name() ==
            graph.GetNode(0).method().name()) {
      // Mutated through static field mutation.
      if (!google::protobuf::util::MessageDifferencer::Equals(
              mutated_graph.GetNode(0).request(), graph.GetNode(0).request())) {
        static_field_changed = true;
        break;
      }
    }
  }

  EXPECT_TRUE(static_field_changed);
}

TEST_F(RpcDomainTest, FromValueTransformsSequenceToRpcGraph) {
  RpcSequence sequence = {GetLogInUserNode(), GetLogOutUserNode(),
                          GetGetUserPostsNode()};

  RpcSessionImpl<MiniBlogger> rpc_domain;
  std::optional<RpcDataFlowGraph> graph = rpc_domain.FromValue(sequence);

  ASSERT_TRUE(graph.has_value());

  ASSERT_EQ(graph->NodeNum(), 3);
  std::vector<RpcNode> all_nodes{graph->GetNode(0), graph->GetNode(1),
                                 graph->GetNode(2)};
  EXPECT_EQ(all_nodes, sequence);
}

TEST_F(RpcDomainTest, ParseCorpusInClearTextFromReturnsRpcDataFlowGraph) {
  constexpr absl::string_view kObjectText =
      R"(FUZZTESTv1
        sub {
          sub { s: "fuzztest.internal.MiniBlogger.LogInUser" }
          sub { s: "" }
          sub {  }
        }
        sub {
          sub { s: "fuzztest.internal.MiniBlogger.LogOutUser" }
          sub { s: "" }
          sub {
            sub {
              sub { i: 0 }
              sub { s: "session_id" }
              sub { s: "log_out_info.session_info.session_id" }
            }
          }
        })";
  std::optional<IRObject> obj = IRObject::FromString(kObjectText);
  ASSERT_TRUE(obj.has_value());

  RpcNode log_in_user_node = GetLogInUserNode();
  RpcNode log_out_user_node = GetLogOutUserNode();
  RpcDataFlowEdge edge = {
      0, GetFieldPath<LogInUserResponse>("session_id"),
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id")};
  log_out_user_node.AddDependency(edge);
  RpcDataFlowGraph graph;
  graph.AddNode(0, log_in_user_node);
  graph.AddNode(1, log_out_user_node);
  RpcSessionImpl<MiniBlogger> rpc_domain;
  auto obj2 = rpc_domain.SerializeCorpus(graph);
  EXPECT_EQ(obj->ToString(), obj2.ToString());
}

TEST_F(RpcDomainTest, ParseCorpusReturnsRpcDataFlowGraph) {
  RpcNode log_in_user_node = GetLogInUserNode();
  RpcNode log_out_user_node = GetLogOutUserNode();
  RpcDataFlowEdge edge = {
      0, GetFieldPath<LogInUserResponse>("session_id"),
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id")};
  log_out_user_node.AddDependency(edge);

  /* Set up log_in_user_node */
  IRObject log_in_user_node_obj;
  auto& log_in_user_node_subs = log_in_user_node_obj.MutableSubs();
  log_in_user_node_subs.push_back(
      IRObject::FromCorpus(log_in_user_node.method().full_name()));
  log_in_user_node_subs.push_back(
      IRObject::FromCorpus(log_in_user_node.request().SerializeAsString()));
  log_in_user_node_subs.push_back(IRObject{});

  /* Set up log_out_user_node*/
  IRObject log_out_user_node_obj;
  auto& log_out_user_node_subs = log_out_user_node_obj.MutableSubs();
  log_out_user_node_subs.push_back(
      IRObject::FromCorpus(log_out_user_node.method().full_name()));
  log_out_user_node_subs.push_back(
      IRObject::FromCorpus(log_out_user_node.request().SerializeAsString()));
  IRObject edge_obj;
  auto& edge_subs = edge_obj.MutableSubs();
  edge_subs.push_back(IRObject::FromCorpus(edge.from_node_id));
  edge_subs.push_back(IRObject::FromCorpus(edge.from_field.ToString()));
  edge_subs.push_back(IRObject::FromCorpus(edge.to_field.ToString()));
  IRObject edges;
  edges.MutableSubs().push_back(edge_obj);
  log_out_user_node_subs.push_back(edges);

  IRObject obj;
  auto& subs = obj.MutableSubs();
  subs.push_back(log_in_user_node_obj);
  subs.push_back(log_out_user_node_obj);

  RpcSessionImpl<MiniBlogger> rpc_domain;
  auto graph = rpc_domain.ParseCorpus(obj);
  ASSERT_TRUE(graph.has_value());
  EXPECT_EQ(graph->NodeNum(), 2);
  EXPECT_EQ(graph->GetNode(0), log_in_user_node);
  EXPECT_EQ(graph->GetNode(1), log_out_user_node);
}

TEST_F(RpcDomainTest, SerializesCorpusReturnsIRObjectOfSpecificStructure) {
  RpcNode log_in_user_node = GetLogInUserNode();
  RpcNode log_out_user_node = GetLogOutUserNode();
  log_out_user_node.AddDependency(RpcDataFlowEdge{
      0, GetFieldPath<LogInUserResponse>("session_id"),
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id")});
  RpcDataFlowGraph graph;
  graph.AddNode(0, log_in_user_node);
  graph.AddNode(1, log_out_user_node);

  RpcSessionImpl<MiniBlogger> rpc_domain;
  IRObject obj = rpc_domain.SerializeCorpus(graph);

  EXPECT_THAT(
      obj,
      SubsAre(
          /*log_in_user_node*/
          SubsAre(ValueIs<std::string>(log_in_user_method_.full_name()),
                  ValueIs<std::string>(
                      log_in_user_node.request().SerializeAsString()),
                  ValueIs<std::monostate>({})),
          /*log_out_user_node*/
          SubsAre(
              ValueIs<std::string>(log_out_user_method_.full_name()),
              ValueIs<std::string>(
                  log_out_user_node.request().SerializeAsString()),
              /*dependencies*/
              SubsAre(SubsAre(
                  ValueIs<std::uint64_t>(0) /*from_node_id*/,
                  ValueIs<std::string>("session_id") /*from_field*/,
                  ValueIs<
                      std::string>(/*to_field*/
                                   "log_out_info.session_info.session_id"))))));
}

TEST_F(RpcDomainTest, SerializesCorpusAndParsesCorpusReturnTheSameObject) {
  RpcSessionImpl<MiniBlogger> rpc_domain;
  for (int i = 0; i < 100; ++i) {
    RpcDataFlowGraph graph = CreateRandomGraph(rpc_domain);
    EXPECT_THAT(rpc_domain.ParseCorpus(rpc_domain.SerializeCorpus(graph)),
                Optional(Eq(graph)));
  }
}

TEST_F(RpcDomainTest, ValidRpcNodeShouldOnlyDependOnPreviousNodes) {
  RpcNode log_out_user_node = GetLogOutUserNode();
  log_out_user_node.AddDependency(RpcDataFlowEdge{
      0, GetFieldPath<LogInUserResponse>("session_id"),
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id")});

  RpcDataFlowGraph graph;
  graph.AddNode(0, log_out_user_node);

  RpcSessionImpl<MiniBlogger> rpc_domain;
  EXPECT_THAT(
      rpc_domain.ValidateCorpusValue(graph),
      IsInvalid(
          "The dependencies should only come from previously executed nodes."));
}

TEST_F(RpcDomainTest, ValidRpcNodeDependencyMatchesPotentialDependency) {
  RpcNode log_out_user_node = GetLogOutUserNode();
  log_out_user_node.AddDependency(RpcDataFlowEdge{
      0, GetFieldPath<RegisterUserResponse>("success"),
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id")});

  RpcDataFlowGraph graph;
  graph.AddNode(0, GetLogInUserNode());
  graph.AddNode(1, log_out_user_node);

  RpcSessionImpl<MiniBlogger> rpc_domain;
  EXPECT_THAT(
      rpc_domain.ValidateCorpusValue(graph),
      IsInvalid(
          "The dependency is not defined in the potential data flow graph."));
}

TEST_F(RpcDomainTest,
       ValidRpcNodeShouldHaveAtMostOneDependencyForEachDynamicField) {
  RpcNode log_in_user_node = GetLogInUserNode();
  RpcNode log_out_user_node = GetLogOutUserNode();
  log_out_user_node.AddDependency(RpcDataFlowEdge{
      0, GetFieldPath<LogInUserResponse>("session_id"),
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id")});
  log_out_user_node.AddDependency(RpcDataFlowEdge{
      0, GetFieldPath<LogInUserResponse>("session_id"),
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id")});

  RpcDataFlowGraph graph;
  graph.AddNode(0, log_in_user_node);
  graph.AddNode(1, log_out_user_node);

  RpcSessionImpl<MiniBlogger> rpc_domain;
  EXPECT_THAT(
      rpc_domain.ValidateCorpusValue(graph),
      IsInvalid("One sink field should have at most one concrete dependency!"));
}

TEST_F(RpcDomainTest, ValidRpcNodePassValidationTest) {
  RpcNode log_in_user_node = GetLogInUserNode();
  RpcNode log_out_user_node = GetLogOutUserNode();
  log_out_user_node.AddDependency(RpcDataFlowEdge{
      0, GetFieldPath<LogInUserResponse>("session_id"),
      GetFieldPath<LogOutUserRequest>("log_out_info.session_info.session_id")});

  RpcDataFlowGraph graph;
  graph.AddNode(0, log_in_user_node);
  graph.AddNode(1, log_out_user_node);

  RpcSessionImpl<MiniBlogger> rpc_domain;
  EXPECT_OK(rpc_domain.ValidateCorpusValue(graph));
}
}  // namespace

}  // namespace fuzztest::internal
