#include "command_security.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "benchmark_fixtures.h"

static long allocation, fail_at = -1;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void *__wrap_malloc(size_t n)
{
    return allocation++ == fail_at ? NULL : __real_malloc(n);
}
void *__wrap_calloc(size_t n, size_t s)
{
    return allocation++ == fail_at ? NULL : __real_calloc(n, s);
}
void *__wrap_realloc(void *p, size_t n)
{
    return allocation++ == fail_at ? NULL : __real_realloc(p, n);
}

static bool verify(const char *message, const char *operation, const char *target, const char *key)
{
    yyjson_mut_doc *doc = nm_command_verify_mldsa_event(
        message, strlen(message), operation, target, (const unsigned char *)key, strlen(key) + 1);
    bool ok = yyjson_mut_is_obj(yyjson_mut_doc_get_root(doc));
    yyjson_mut_doc_free(doc);
    return ok;
}

int main(void)
{
    const char *fixtures[] = {benchmark_mldsa_0, benchmark_mldsa_50};
    for (size_t i = 0; i < 2; ++i) {
        const char *input = fixtures[i];
        assert(verify(input, "processorInit", benchmark_target, benchmark_mldsa_public));
        assert(!verify(input, "wrong-operation", benchmark_target, benchmark_mldsa_public));
        assert(!verify(input, "processorInit", "wrong-device", benchmark_mldsa_public));
        assert(!verify(input, "processorInit", benchmark_target, benchmark_public));
        assert(!verify(input, "processorInit", benchmark_target, "invalid"));
        char *copy = nm_bulk_strdup(input);
        assert(copy);
        char *auth = strstr(copy, "benchmark-only");
        assert(auth);
        auth[0] = 'X';
        assert(!verify(copy, "processorInit", benchmark_target, benchmark_mldsa_public));
        free(copy);
        copy = nm_bulk_strdup(input);
        assert(copy);
        char *sig = strstr(copy, "\"BackendSignature\":\"");
        assert(sig);
        sig += strlen("\"BackendSignature\":\"");
        sig[0] = sig[0] == 'A' ? 'B' : 'A';
        assert(!verify(copy, "processorInit", benchmark_target, benchmark_mldsa_public));
        free(copy);
        for (size_t n = 0; n < strlen(input); n += strlen(input) / 12 + 1)
            assert(!nm_command_verify_mldsa_event(input, n, "processorInit", benchmark_target,
                                                  (const unsigned char *)benchmark_mldsa_public,
                                                  sizeof(benchmark_mldsa_public)));
    }
    assert(!verify(benchmark_ecdsa_0, "processorInit", benchmark_target, benchmark_mldsa_public));
    assert(!verify("{\"data\":{},\"data\":{}}", "processorInit", benchmark_target,
                   benchmark_mldsa_public));
    allocation = 0;
    assert(verify(benchmark_mldsa_50, "processorInit", benchmark_target, benchmark_mldsa_public));
    long allocations = allocation;
    for (long i = 0; i < allocations; ++i) {
        allocation = 0;
        fail_at = i;
        assert(
            !verify(benchmark_mldsa_50, "processorInit", benchmark_target, benchmark_mldsa_public));
        fail_at = -1;
    }
    printf("MLDSA_COMMAND_ALLOCATION_PASS allocations=%ld\n", allocations);
    puts("MLDSA_COMMAND_TEST_PASS: production .NET 0/50-host signatures; tampering, wrong route, "
         "wrong key, truncated JSON and ECDSA rejected");
    return 0;
}
