#ifndef NM_TEST_TRANSPORT_H
#define NM_TEST_TRANSPORT_H
typedef void *esp_transport_handle_t;
typedef void *esp_tls_error_handle_t;
esp_tls_error_handle_t esp_transport_get_error_handle(esp_transport_handle_t);
int esp_transport_get_errno(esp_transport_handle_t);
esp_transport_handle_t esp_transport_init(void);
void *esp_transport_get_context_data(esp_transport_handle_t);
int esp_transport_set_context_data(esp_transport_handle_t, void *);
int esp_transport_destroy(esp_transport_handle_t);
int esp_transport_set_func(esp_transport_handle_t,
                           int (*)(esp_transport_handle_t, const char *, int, int),
                           int (*)(esp_transport_handle_t, char *, int, int),
                           int (*)(esp_transport_handle_t, const char *, int, int),
                           int (*)(esp_transport_handle_t), int (*)(esp_transport_handle_t, int),
                           int (*)(esp_transport_handle_t, int), int (*)(esp_transport_handle_t));
int esp_transport_connect_async(esp_transport_handle_t, const char *, int, int);
int esp_transport_read(esp_transport_handle_t, char *, int, int);
int esp_transport_write(esp_transport_handle_t, const char *, int, int);
int esp_transport_poll_read(esp_transport_handle_t, int);
int esp_transport_poll_write(esp_transport_handle_t, int);
#endif
