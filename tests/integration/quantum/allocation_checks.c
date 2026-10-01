/* Link-time malloc failures exercise the real provider and wolfSSL cleanup. */
#define _POSIX_C_SOURCE 200809L
#include "quantum_tls.h"
#include <assert.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
static size_t allocation, fail_at;
static bool fail(void)
{
    return ++allocation == fail_at;
}
void *__wrap_malloc(size_t bytes)
{
    return fail() ? NULL : __real_malloc(bytes);
}
void *__wrap_calloc(size_t count, size_t bytes)
{
    return fail() ? NULL : __real_calloc(count, bytes);
}
void *__wrap_realloc(void *old, size_t bytes)
{
    return fail() ? NULL : __real_realloc(old, bytes);
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    FILE *file = fopen(argv[1], "rb");
    if (!file)
        return 2;
    unsigned char pem[65536];
    size_t length = fread(pem, 1, sizeof(pem), file);
    bool invalid = ferror(file) || !feof(file);
    fclose(file);
    if (invalid || !length)
        return 2;
    /* Warm the once-only library before independent allocation failures. */
    nm_quantum_tls *provider = nm_quantum_tls_new(pem, length);
    assert(provider);
    nm_quantum_tls_free(provider);
    allocation = 0;
    provider = nm_quantum_tls_new(pem, length);
    assert(provider);
    size_t provider_allocations = allocation;
    nm_quantum_tls_free(provider);
    for (size_t i = 1; i <= provider_allocations; ++i) {
        allocation = 0;
        fail_at = i;
        provider = nm_quantum_tls_new(pem, length);
        fail_at = 0;
        /* Optional library allocations can fail harmlessly. Either result must
         * remain safe to free; required failures must not expose partial ctx. */
        nm_quantum_tls_free(provider);
    }
    provider = nm_quantum_tls_new(pem, length);
    assert(provider);
    struct addrinfo address = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
    size_t probe_allocations[2];
    for (unsigned certificate = 0; certificate < 2; ++certificate) {
        allocation = 0;
        nm_quantum_result r = nm_quantum_tls_probe(provider, certificate, "localhost", &address,
                                                   nm_quantum_now_ms() - 1);
        assert(r.outcome == NM_QUANTUM_TIMEOUT);
        probe_allocations[certificate] = allocation;
        nm_quantum_result_free(&r);
        for (size_t i = 1; i <= probe_allocations[certificate]; ++i) {
            allocation = 0;
            fail_at = i;
            r = nm_quantum_tls_probe(provider, certificate, "localhost", &address,
                                     nm_quantum_now_ms() - 1);
            fail_at = 0;
            assert(r.outcome == NM_QUANTUM_TIMEOUT || r.outcome == NM_QUANTUM_LOCAL_FAILURE);
            nm_quantum_result_free(&r);
        }
    }
    nm_quantum_tls_free(provider);
    printf("ALLOCATION_CHECKS provider=%zu quantum=%zu certificate=%zu passed\n",
           provider_allocations, probe_allocations[0], probe_allocations[1]);
    return 0;
}
