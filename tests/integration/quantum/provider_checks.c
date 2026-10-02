#define _POSIX_C_SOURCE 200809L
#include "quantum_tls.h"
#include <assert.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    nm_quantum_tls *provider;
    const struct addrinfo *addresses;
    const char *host;
    bool certificate, timeout, cancel;
    unsigned repeats, failed;
} job;
static atomic_bool cancellation;
static void *cancel_after_delay(void *unused)
{
    (void)unused;
    struct timespec delay = {.tv_nsec = 100000000};
    nanosleep(&delay, NULL);
    atomic_store(&cancellation, true);
    return NULL;
}
static void *run(void *argument)
{
    job *j = argument;
    for (unsigned i = 0; i < j->repeats; ++i) {
        int64_t start = nm_quantum_now_ms();
        nm_quantum_result r = j->cancel
            ? nm_quantum_tls_probe_cancelable(j->provider, true, j->host, j->addresses,
                                               start + 15000, &cancellation)
            : nm_quantum_tls_probe(j->provider, j->certificate, j->host, j->addresses,
                                    start + (j->timeout ? 100 : 15000));
        if (r.outcome != (j->cancel ? NM_QUANTUM_CANCELLED : j->timeout ? NM_QUANTUM_TIMEOUT : NM_QUANTUM_OK))
            ++j->failed;
        if (r.outcome == NM_QUANTUM_OK && r.error)
            ++j->failed;
        if ((j->timeout || j->cancel) && nm_quantum_now_ms() - start > 500)
            ++j->failed;
        nm_quantum_result_free(&r);
        assert(!r.summary);
    }
    return NULL;
}
int main(int argc, char **argv)
{
    if (argc != 7)
        return 2;
    char *end;
    unsigned long count = strtoul(argv[5], &end, 10);
    if (*end || count < 1 || count > 8)
        return 2;
    unsigned long repeats = strtoul(argv[6], &end, 10);
    if (*end || repeats < 1 || repeats > 16)
        return 2;
    assert(!nm_quantum_tls_new(NULL, 1));
    assert(!nm_quantum_tls_new((const unsigned char *)"invalid", 0));
    assert(!nm_quantum_tls_new((const unsigned char *)"invalid", 7));
    FILE *file = fopen(argv[4], "rb");
    if (!file)
        return 2;
    unsigned char pem[65536];
    size_t length = fread(pem, 1, sizeof(pem), file);
    bool failed_read = ferror(file) || !feof(file);
    fclose(file);
    if (failed_read)
        return 2;
    nm_quantum_tls *provider = nm_quantum_tls_new(pem, length);
    if (!provider)
        return 2;
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM, .ai_family = AF_UNSPEC}, *addresses = NULL;
    if (getaddrinfo(argv[2], argv[3], &hints, &addresses)) {
        nm_quantum_tls_free(provider);
        return 2;
    }
    nm_quantum_result expired =
        nm_quantum_tls_probe(provider, false, argv[2], addresses, nm_quantum_now_ms() - 1);
    assert(expired.outcome == NM_QUANTUM_TIMEOUT);
    nm_quantum_result_free(&expired);
    nm_quantum_result invalid =
        nm_quantum_tls_probe(provider, false, "", addresses, nm_quantum_now_ms() + 100);
    assert(invalid.outcome == NM_QUANTUM_ERROR);
    nm_quantum_result_free(&invalid);
    if (!strcmp(argv[1], "policy")) {
        /* Observing an untrusted certificate must not change the shared
         * provider's policy for the following authenticated quantum probe. */
        nm_quantum_result observed =
            nm_quantum_tls_probe(provider, true, argv[2], addresses, nm_quantum_now_ms() + 15000);
        assert(observed.outcome == NM_QUANTUM_OK && observed.summary);
        nm_quantum_result_free(&observed);
        nm_quantum_result verified =
            nm_quantum_tls_probe(provider, false, argv[2], addresses, nm_quantum_now_ms() + 15000);
        assert(verified.outcome == NM_QUANTUM_ERROR && verified.error);
        nm_quantum_result_free(&verified);
        freeaddrinfo(addresses);
        nm_quantum_tls_free(provider);
        puts("PROVIDER_POLICY certificate observed; subsequent untrusted quantum rejected");
        return 0;
    }
    pthread_t threads[8];
    pthread_t canceller;
    bool cancel = !strcmp(argv[1], "cancel");
    atomic_init(&cancellation, false);
    if (cancel) assert(!pthread_create(&canceller, NULL, cancel_after_delay, NULL));
    job jobs[8];
    size_t started = 0;
    for (; started < count; ++started) {
        jobs[started] = (job){.provider = provider,
                              .addresses = addresses,
                              .host = argv[2],
                              .certificate = !strcmp(argv[1], "quantumcert"),
                              .timeout = !strcmp(argv[1], "timeout"),
                              .cancel = cancel,
                              .repeats = (unsigned)repeats};
        if (pthread_create(&threads[started], NULL, run, &jobs[started]))
            break;
    }
    unsigned failures = started != count;
    for (size_t i = 0; i < started; ++i) {
        pthread_join(threads[i], NULL);
        failures += jobs[i].failed;
    }
    if (cancel) assert(!pthread_join(canceller, NULL));
    freeaddrinfo(addresses);
    nm_quantum_tls_free(provider);
    printf("PROVIDER_CHECKS workers=%lu repeats=%lu failures=%u\n", count, repeats, failures);
    return failures ? 1 : 0;
}
