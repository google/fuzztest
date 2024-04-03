#include "./fuzztest/internal/configuration.h"

#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"

namespace fuzztest::internal {
namespace {

// Compares the fields of `Configuration` that are relevant for serialization.
MATCHER_P(IsOkAndEquals, config, "") {
  const absl::StatusOr<Configuration>& other = arg;
  return other.ok() && config.corpus_database == other->corpus_database &&
         config.binary_identifier == other->binary_identifier &&
         config.reproduce_findings_as_separate_tests ==
             other->reproduce_findings_as_separate_tests &&
         config.replay_coverage_inputs == other->replay_coverage_inputs &&
         config.stack_limit == other->stack_limit &&
         config.rss_limit == other->rss_limit &&
         config.time_limit_per_input == other->time_limit_per_input &&
         config.crashing_input_to_reproduce ==
             other->crashing_input_to_reproduce;
}

TEST(ConfigurationTest,
     DeserializeYieldsSerializedConfigurationWithoutOptionalValues) {
  Configuration configuration{"corpus_database",
                              "binary_identifier",
                              /*reproduce_findings_as_separate_tests=*/true,
                              /*replay_coverage_inputs=*/false,
                              /*stack_limit=*/100,
                              /*rss_limit=*/200,
                              /*time_limit_per_input=*/absl::Seconds(42),
                              /*crashing_input_to_reproduce=*/std::nullopt,
                              /*reproduction_command_template=*/std::nullopt};

  EXPECT_THAT(Configuration::Deserialize(configuration.Serialize()),
              IsOkAndEquals(configuration));
}

TEST(ConfigurationTest,
     DeserializeYieldsSerializedConfigurationWithOptionalValues) {
  Configuration configuration{"corpus_database",
                              "binary_identifier",
                              /*reproduce_findings_as_separate_tests=*/true,
                              /*replay_coverage_inputs=*/false,
                              /*stack_limit=*/100,
                              /*rss_limit=*/200,
                              /*time_limit_per_input=*/absl::Seconds(42),
                              "crashing_input_to_reproduce",
                              "reproduction_command_template"};

  EXPECT_THAT(Configuration::Deserialize(configuration.Serialize()),
              IsOkAndEquals(configuration));
}

TEST(ConfigurationTest, DeserializeFailsOnNonsenseInput) {
  EXPECT_FALSE(
      Configuration::Deserialize("Not a serialized configuration").ok());
}

}  // namespace
}  // namespace fuzztest::internal
