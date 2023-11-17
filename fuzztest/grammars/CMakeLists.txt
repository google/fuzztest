function(fuzztest_grammar_library lib_name top_level_rule)
  if (ARGN)
    set(${lib_name}_grammar_files "")
    set(${lib_name}_output_file ${lib_name}.h)
    foreach(grammar_file ${ARGN})
      get_filename_component(abs_path ${grammar_file} ABSOLUTE)
      list(APPEND ${lib_name}_grammar_files ${abs_path})
    endforeach()
    string(JOIN "," all_grammar_files ${${lib_name}_grammar_files})

    add_custom_command(
      OUTPUT ${${lib_name}_output_file}
      COMMAND
        $<TARGET_FILE:grammar_domain_code_generator>
        --top_level_rule ${top_level_rule}
        --input_grammar_files ${all_grammar_files}
        --output_header_file_path
          ${CMAKE_CURRENT_BINARY_DIR}/${${lib_name}_output_file}
      DEPENDS ${${lib_name}_grammar_files}
    )

    add_library(
      ${lib_name}
      INTERFACE
      ${${lib_name}_output_file}
    )

    target_include_directories(
      ${lib_name}
      INTERFACE
      ${CMAKE_CURRENT_BINARY_DIR}/..
    )

    add_dependencies(
      ${lib_name}
      grammar_domain_code_generator
    )
  else()
    message(FATAL_ERROR "No grammar files specified!")
  endif()
endfunction()

fuzztest_grammar_library("json_grammar" "json" ./JSON.g4)
