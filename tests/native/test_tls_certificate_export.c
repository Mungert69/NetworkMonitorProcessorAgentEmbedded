/* Inspect the actual private exporter using provider API stand-ins. Other TLS
 * functions in the included production module are discarded by the linker. */
#include "../../firmware/main/quantum_tls.c"
#include <assert.h>

static int certificates = 2, bytes = 128, fail_index = -1;
static bool fail_allocation, oversized_write, zero_write;
static void *owned;
static unsigned writes;
void *__real_malloc(size_t);
void __real_free(void *);
void *__wrap_malloc(size_t size)
{
    if (fail_allocation)
        return NULL;
    void *result = __real_malloc(size);
    assert(!owned);
    owned = result;
    return result;
}
void __wrap_free(void *pointer)
{
    if (pointer) {
        assert(pointer == owned);
        owned = NULL;
    }
    __real_free(pointer);
}
WOLFSSL_X509_CHAIN *wolfSSL_get_peer_chain(WOLFSSL *ssl)
{
    return (WOLFSSL_X509_CHAIN *)ssl;
}
int wolfSSL_get_chain_count(WOLFSSL_X509_CHAIN *chain)
{
    assert(chain);
    return certificates;
}
int wolfSSL_get_chain_length(WOLFSSL_X509_CHAIN *chain, int index)
{
    assert(chain && index >= 0 && index < certificates);
    return bytes;
}
int wolfSSL_get_chain_cert_pem(WOLFSSL_X509_CHAIN *chain, int index, unsigned char *buffer,
                               int capacity, int *written)
{
    assert(chain && capacity > 4 && buffer && written);
    ++writes;
    if (index == fail_index)
        return WOLFSSL_FAILURE;
    memcpy(buffer, "PEM\n", 4);
    *written = oversized_write ? capacity + 1 : zero_write ? 0 : 4;
    return WOLFSSL_SUCCESS;
}
int main(void)
{
    WOLFSSL *session = (WOLFSSL *)(uintptr_t)1;
    char *pem = export_chain(session);
    assert(pem && !strcmp(pem, "PEM\nPEM\n") && writes == 2);
    free(pem);
    assert(!owned);
    fail_allocation = true;
    assert(!export_chain(session) && !owned);
    fail_allocation = false;
    fail_index = 1;
    assert(!export_chain(session) && !owned);
    fail_index = -1;
    oversized_write = true;
    assert(!export_chain(session) && !owned);
    oversized_write = false;
    zero_write = true;
    assert(!export_chain(session) && !owned);
    zero_write = false;
    for (int count = -1; count <= 17; ++count) {
        certificates = count;
        bytes = 16384;
        pem = export_chain(session);
        assert((count == 1) == (pem != NULL));
        free(pem);
        assert(!owned);
    }
    certificates = 1;
    for (int length = -1; length <= 0; ++length) {
        bytes = length;
        assert(!export_chain(session) && !owned);
    }
    bytes = 16385;
    assert(!export_chain(session) && !owned);
    puts("Certificate chain bounds/partial failures/ownership tests passed");
    return 0;
}
