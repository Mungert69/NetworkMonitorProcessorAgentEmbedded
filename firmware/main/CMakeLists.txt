idf_component_register(
    SRCS
        "main.c" "ble_scanner.c"
        # Provisioning, persistent configuration and platform networking.
        "config.c" "config_reset.c" "network.c" "serial_console.c" "wifi_setup.c"
        "enrollment.c" "enrollment_http.c" "enrollment_oauth.c" "enrollment_registration.c"
        # Runtime orchestration and message boundaries.
        "processor.c" "processor_mqtt.c" "processor_commands.c"
        "processor_messages.c" "processor_ota.c" "message_publish.c" "command_security.c"
        # Bounded concurrent endpoint probing (model stays single-writer).
        "nm_probe_pool.c"
        # Typed model, snapshots and persistence.
        "state.c" "monitor_model.c" "monitor_record.c" "monitor_snapshot.c"
        "monitor_numbers.c" "monitor_schedule.c" "storage.c"
        # Endpoint implementations and firmware installation.
        "endpoints.c" "endpoint_common.c" "endpoint_dns.c" "endpoint_dns_task.c" "endpoint_icmp.c"
        "endpoint_tcp.c" "endpoint_http.c" "endpoint_ble.c" "http_deadline.c" "ota.c"
        "../../third_party/yyjson/src/yyjson.c"
    INCLUDE_DIRS "../../third_party/yyjson/src"
    EMBED_TXTFILES "command-signing-public.pem"
    REQUIRES esp_psram spi_flash esp_wifi esp_event esp_netif nvs_flash
             mqtt mbedtls lwip esp_http_client tcp_transport esp_timer esp_https_ota
             app_update bt espressif__brotli)
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    YYJSON_DISABLE_UTILS=1 YYJSON_DISABLE_INCR_READER=1 YYJSON_DISABLE_NON_STANDARD=1)
