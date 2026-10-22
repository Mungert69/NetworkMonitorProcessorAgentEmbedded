# Espressif's Brotli 1.2.1 package excludes scripts/*.pc.in, although its
# upstream CMakeLists.txt reads them even with install disabled. Restore only
# these build metadata templates; never alter the managed C sources.
function(nm_prepare_brotli_pkgconfig component_dir)
  file(READ "${component_dir}/idf_component.yml" manifest)
  if(NOT manifest MATCHES "version: 1\\.2\\.1")
    message(FATAL_ERROR "Review Brotli pkg-config workaround for the new component version")
  endif()
  foreach(name libbrotlicommon libbrotlidec libbrotlienc)
    set(destination "${component_dir}/brotli/scripts/${name}.pc.in")
    if(NOT EXISTS "${destination}")
      configure_file("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/brotli-pkgconfig/${name}.pc.in"
        "${destination}" COPYONLY)
    endif()
  endforeach()
endfunction()
