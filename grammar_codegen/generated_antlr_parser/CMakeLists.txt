add_library(
  generated_antlr_parser
  STATIC
  ANTLRv4Lexer.cpp
  ANTLRv4Parser.cpp
  ANTLRv4ParserBaseListener.cpp
  ANTLRv4ParserListener.cpp
)

target_link_libraries(
  generated_antlr_parser
  PUBLIC
  antlr4_static
)

target_include_directories(
  generated_antlr_parser
  PUBLIC
  ${antlr_cpp_SOURCE_DIR}/runtime/src
  ${CMAKE_CURRENT_SOURCE_DIR}
)