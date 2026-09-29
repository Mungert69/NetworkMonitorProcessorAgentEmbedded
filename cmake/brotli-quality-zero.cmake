# Apply to the upstream brotlienc target after add_subdirectory/component setup.
# Retain its public API and source algorithms; replace only encode.c in the build.
function(nm_brotli_quality_zero target upstream python)
  set(generator "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../tools/specialize_brotli.py")
  set(input "${upstream}/c/enc/encode.c")
  set(output "${CMAKE_CURRENT_BINARY_DIR}/brotli-quality-zero/encode.c")
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${generator}" "${input}")
  execute_process(COMMAND "${python}" "${generator}" "${input}" "${output}"
    RESULT_VARIABLE result)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "Failed to specialize pinned Brotli encoder")
  endif()
  get_target_property(sources ${target} SOURCES)
  # Q0's dependency closure: exclude the two-pass, reference-search and
  # dictionary sources. --gc-sections drops unused helpers in shared sources.
  list(FILTER sources INCLUDE REGEX "(^|/)(compress_fragment|brotli_bit_stream|entropy_encode|fast_log|memory|static_init|metablock)\\.c$")
  set_property(TARGET ${target} PROPERTY SOURCES "${sources};${output}")
  target_include_directories(${target} PRIVATE "${upstream}/c/enc")
  # Needed on native tests too: discard unreferenced encoder functions/tables.
  target_compile_options(${target} PRIVATE -ffunction-sections -fdata-sections)
  # Upstream otherwise terminates the process on allocation failure.
  target_compile_definitions(${target} PRIVATE BROTLI_ENCODER_CLEANUP_ON_OOM)
endfunction()
