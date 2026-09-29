#define ESP_TLS_ERR_SSL_WANT_READ (-0x6900)
#define ESP_TLS_ERR_SSL_WANT_WRITE (-0x6880)
int esp_tls_get_and_clear_last_error(void *, int *, int *);
