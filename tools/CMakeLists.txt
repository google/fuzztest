add_executable(
  grammar_domain_code_generator
  grammar_domain_code_generator.cc
)

target_link_libraries(
  grammar_domain_code_generator
  absl::flags
  absl::flags_parse
  fuzztest_logging
  code_generation
)