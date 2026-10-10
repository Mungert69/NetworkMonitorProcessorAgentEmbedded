idf_component_register(
    SRCS
        "main.c" "ble_scanner.c" "ble_buffer.c" "ble_cycle.c"
        # Provisioning, persistent configuration and platform networking.
        "config.c" "config_reset.c" "network.c" "serial_console.c" "wifi_setup.c"
        "enrollment.c" "enrollment_http.c" "enrollment_oauth.c" "enrollment_registration.c"
        # Runtime orchestration and message boundaries.
        "processor.c" "processor_mqtt.c" "processor_commands.c"
        "processor_cmd.c" "cmd_processor_message.c" "quantum_cert_cmd_processor.c"
        "quantum_connect_cmd_processor.c" "cmd_arguments.c"
        "cmd_processor_catalog.c" "cmd_output.c" "quantum_port_scanner_cmd_processor.c"
        "quantum_info_cmd_processor.c" "openssl_cmd_processor.c" "openssl_arguments.c" "nmap_cmd_processor.c"
        "processor_messages.c" "processor_ota.c" "message_publish.c" "command_security.c" "command_mldsa.c"
        # Bounded concurrent endpoint probing (model stays single-writer).
        "nm_probe_pool.c"
        # Typed model, snapshots and persistence.
        "state.c" "monitor_model.c" "monitor_record.c" "monitor_snapshot.c"
        "monitor_numbers.c" "monitor_schedule.c" "storage.c"
        # Endpoint implementations and firmware installation.
        "endpoints.c" "endpoint_common.c" "endpoint_dns.c" "endpoint_dns_task.c" "endpoint_icmp.c"
        "endpoint_nmap.c" "nmap_runner_embedded.c" "nmap_targets.c" "nmap_arp.c"
        "service_hints.c"
        "endpoint_tcp.c" "endpoint_http.c" "endpoint_ble.c" "ble_decoder.c" "ble_crypto.c" "ble_metric.c" "ble_victron_decoder.c" "ble_victron_records.c" "ble_ruuvi_decoder.c" "ble_bthome_decoder.c" "http_deadline.c" "ota.c"
        "endpoint_quantum.c" "tls_inspection.c" "quantum_tls.c" "openssl_runner.c"
        "../../third_party/yyjson/src/yyjson.c"
    INCLUDE_DIRS "../../third_party/yyjson/src"
    EMBED_TXTFILES "command-signing-public.pem" "command-signing-mldsa-public.pem"
                   "service-hints.csv"
    REQUIRES esp_psram spi_flash esp_wifi esp_event esp_netif nvs_flash
             mqtt mbedtls lwip esp_http_client tcp_transport esp_timer esp_https_ota
             app_update bt espressif__brotli quantum_wolfssl)
# Observe fresh ARP replies without replacing the driver input callback or
# changing lwIP's cache. The wrapper forwards every packet to the real handler.
target_link_options(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=etharp_input")
if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    # Use IDF's public Mozilla roots, never the host store or a private test CA.
    configure_file("$ENV{IDF_PATH}/components/mbedtls/esp_crt_bundle/cacrt_all.pem"
        "${CMAKE_CURRENT_BINARY_DIR}/quantum_roots.pem" COPYONLY)
    target_add_binary_data(${COMPONENT_LIB}
        "${CMAKE_CURRENT_BINARY_DIR}/quantum_roots.pem" TEXT)
endif()
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    YYJSON_DISABLE_UTILS=1 YYJSON_DISABLE_INCR_READER=1 YYJSON_DISABLE_NON_STANDARD=1)
if(NM_COMMAND_BENCHMARK_FIXTURES AND NOT CMAKE_BUILD_EARLY_EXPANSION)
    target_sources(${COMPONENT_LIB} PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../../tests/integration/command_benchmark/benchmark.c")
    target_include_directories(${COMPONENT_LIB} PRIVATE "${NM_COMMAND_BENCHMARK_FIXTURES}")
    target_compile_definitions(${COMPONENT_LIB} PRIVATE NM_COMMAND_BENCHMARK)
    if(NM_COMMAND_MLDSA_BENCHMARK)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE NM_COMMAND_MLDSA_BENCHMARK)
    endif()
endif()
