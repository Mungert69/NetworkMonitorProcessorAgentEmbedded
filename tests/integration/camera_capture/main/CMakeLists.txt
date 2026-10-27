idf_component_register(SRCS "main.c"
    "../../../../firmware/main/camera_capture.c"
    "../../../../firmware/main/camera_capture_cmd_processor.c"
    "../../../../firmware/main/camera_http.c"
    "../../../../firmware/main/camera_rtsp.c"
    "../../../../firmware/main/camera_socket.c"
    "../../../../firmware/main/camera_jpeg.c"
    "../../../../firmware/main/camera_xml.c"
    "../../../../firmware/main/cmd_arguments.c"
    "../../../../firmware/main/http_deadline.c"
    "../../../../third_party/yyjson/src/yyjson.c"
    INCLUDE_DIRS "../../../../firmware/main" "../../../../third_party/yyjson/src"
    REQUIRES esp_wifi esp_event esp_netif nvs_flash esp_http_client tcp_transport
             esp_timer esp_psram mqtt)
target_compile_options(${COMPONENT_LIB} PRIVATE -UNDEBUG)
string(TIMESTAMP TEST_EPOCH "%s" UTC)
target_compile_definitions(${COMPONENT_LIB} PRIVATE NM_TEST_EPOCH=${TEST_EPOCH})
