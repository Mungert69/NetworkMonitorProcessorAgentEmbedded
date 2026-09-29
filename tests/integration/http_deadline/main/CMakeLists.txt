idf_component_register(SRCS "main.c" "probe_memory.c" "../../../../firmware/main/http_deadline.c"
    "../../../../firmware/main/nm_probe_pool.c"
    "../../../../firmware/main/endpoints.c"
    "../../../../firmware/main/endpoint_common.c"
    "../../../../firmware/main/endpoint_dns.c"
    "../../../../firmware/main/endpoint_dns_task.c"
    "../../../../firmware/main/endpoint_icmp.c"
    "../../../../firmware/main/endpoint_tcp.c"
    "../../../../firmware/main/endpoint_http.c"
    "../../../../firmware/main/endpoint_ble.c"
    "../../../../firmware/main/ble_scanner.c"
    INCLUDE_DIRS "../../../../firmware/main" "../../../../third_party/yyjson/src"
    REQUIRES esp_wifi esp_event esp_netif nvs_flash esp_http_client tcp_transport esp_timer esp_psram mqtt bt)
target_compile_options(${COMPONENT_LIB} PRIVATE -UNDEBUG)
target_link_options(${COMPONENT_LIB} INTERFACE
    "-Wl,--wrap=lwip_getaddrinfo" "-Wl,--wrap=nm_esp_endpoint_run")
string(TIMESTAMP TEST_EPOCH "%s" UTC)
target_compile_definitions(${COMPONENT_LIB} PRIVATE NM_TEST_EPOCH=${TEST_EPOCH})
