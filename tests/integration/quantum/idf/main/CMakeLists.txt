get_filename_component(ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../../.." ABSOLUTE)
if(CMAKE_BUILD_EARLY_EXPANSION)
    idf_component_register(REQUIRES quantum_wolfssl nvs_flash esp_wifi esp_event esp_netif esp_timer)
    return()
endif()
if(NOT IS_ABSOLUTE "${NM_QUANTUM_TRIAL_DIR}")
    message(FATAL_ERROR "Set NM_QUANTUM_TRIAL_DIR to an absolute private fixture directory outside the repository")
endif()
get_filename_component(PRIVATE_DIR "${NM_QUANTUM_TRIAL_DIR}" REALPATH)
file(RELATIVE_PATH PRIVATE_RELATIVE "${ROOT}" "${PRIVATE_DIR}")
if(NOT PRIVATE_RELATIVE MATCHES "^\\.\\./")
    message(FATAL_ERROR "Private quantum configuration must stay outside the repository")
endif()
if(NOT EXISTS "${PRIVATE_DIR}/board_config.h")
    message(FATAL_ERROR "Start board_fixture.py before building the hardware trial")
endif()
idf_component_register(SRCS "main.c" "../../probe.c" "${ROOT}/firmware/main/quantum_tls.c"
    INCLUDE_DIRS "${ROOT}/firmware/main" "${ROOT}/third_party/yyjson/src"
        "${PRIVATE_DIR}"
    REQUIRES quantum_wolfssl nvs_flash esp_wifi esp_event esp_netif esp_timer
    EMBED_TXTFILES "${PRIVATE_DIR}/ca.pem")
set_source_files_properties("../../probe.c" PROPERTIES COMPILE_DEFINITIONS "main=nm_quantum_trial_probe")
