#ifndef NM_TEST_X509_CRT_H
#define NM_TEST_X509_CRT_H
#include <stdint.h>
typedef struct {
    int year, mon, day, hour, min, sec;
} mbedtls_x509_time;
typedef struct {
    mbedtls_x509_time valid_to;
} mbedtls_x509_crt;
#define MBEDTLS_X509_BADCERT_OTHER 0x100U
#endif
