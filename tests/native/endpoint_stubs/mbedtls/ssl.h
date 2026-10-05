/* SDK error value only; no cryptography is mocked by this transport unit test. */
#define MBEDTLS_ERR_SSL_ALLOC_FAILED (-0x7F00)

#include "x509_crt.h"
void mbedtls_ssl_conf_verify(void *, int (*)(void *, mbedtls_x509_crt *, int, uint32_t *), void *);
