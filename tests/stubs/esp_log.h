#ifndef NM_TEST_ESP_LOG_H
#define NM_TEST_ESP_LOG_H
#include <stdarg.h>
/* Consume arguments (including TAG) without flooding failure-injection tests. */
static inline void nm_test_log(const char *tag, const char *format, ...)
{ (void)tag; (void)format; }
#define ESP_LOGE(...) nm_test_log(__VA_ARGS__)
#define ESP_LOGW(...) nm_test_log(__VA_ARGS__)
#define ESP_LOGI(...) nm_test_log(__VA_ARGS__)
#endif
