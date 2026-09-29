idf_component_register(SRCS "main.c" "model_test.c"
    "../../../../firmware/main/monitor_model.c"
    "../../../../firmware/main/monitor_record.c"
    "../../../../firmware/main/monitor_snapshot.c"
    "../../../../firmware/main/monitor_schedule.c"
    "../../../../firmware/main/monitor_numbers.c"
    "../../../../firmware/main/storage.c"
    "../../../../third_party/yyjson/src/yyjson.c"
    INCLUDE_DIRS "../../../../firmware/main" "../../../../third_party/yyjson/src"
    REQUIRES esp_psram esp_timer nvs_flash mqtt espressif__brotli)
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    YYJSON_DISABLE_UTILS=1 YYJSON_DISABLE_INCR_READER=1 YYJSON_DISABLE_NON_STANDARD=1)
target_compile_options(${COMPONENT_LIB} PRIVATE -UNDEBUG)
