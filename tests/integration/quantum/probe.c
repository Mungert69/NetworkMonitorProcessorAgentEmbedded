/* CLI/board adapter: all TCP/TLS/algorithm work is production quantum_tls.c. */
#define _POSIX_C_SOURCE 200809L
#include "quantum_tls.h"
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if ((argc != 5 && argc != 6 && argc != 7) ||
        (strcmp(argv[1], "quantum") && strcmp(argv[1], "quantumcert")))
        return 2;
    unsigned char *owned_pem = NULL;
    const unsigned char *pem;
    size_t length;
#ifdef ESP_PLATFORM
    extern const unsigned char ca_start[] asm("_binary_ca_pem_start");
    extern const unsigned char ca_end[] asm("_binary_ca_pem_end");
    pem = ca_start;
    length = (size_t)(ca_end - ca_start);
#else
    FILE *ca = fopen(argv[4], "rb");
    if (!ca)
        return 2;
    if (fseek(ca, 0, SEEK_END)) {
        fclose(ca);
        return 2;
    }
    long bytes = ftell(ca);
    if (bytes <= 0 || bytes > 1024 * 1024 || fseek(ca, 0, SEEK_SET)) {
        fclose(ca);
        return 2;
    }
    owned_pem = malloc((size_t)bytes);
    if (!owned_pem || fread(owned_pem, 1, (size_t)bytes, ca) != (size_t)bytes) {
        free(owned_pem);
        fclose(ca);
        return 2;
    }
    fclose(ca);
    pem = owned_pem;
    length = (size_t)bytes;
#endif
    nm_quantum_tls *provider = nm_quantum_tls_new(pem, length);
    free(owned_pem);
    if (!provider)
        return 2;
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM, .ai_family = AF_UNSPEC};
    struct addrinfo *addresses = NULL;
    int64_t start = nm_quantum_now_ms();
    /* CLI-only libc DNS. Production endpoint uses bounded nm_endpoint_resolve. */
    if (getaddrinfo(argc >= 6 ? argv[5] : argv[2], argv[3], &hints, &addresses)) {
        nm_quantum_tls_free(provider);
        return 2;
    }
    bool certificate = !strcmp(argv[1], "quantumcert");
    nm_quantum_result result = nm_quantum_tls_probe_group(
        provider, certificate, argv[2], addresses, start + 15000, NULL, argc == 7 ? argv[6] : NULL);
    printf("group=%s elapsed_ms=%lld outcome=%d TLS error=%d\n", result.group,
           (long long)(nm_quantum_now_ms() - start), result.outcome, result.error);
    printf("status=%s\n",
           certificate
               ? (result.outcome == NM_QUANTUM_OK ? "Quantum-safe certificate detected"
                                                  : "Certificate not quantum-safe")
               : (result.outcome == NM_QUANTUM_OK ? "Using quantum safe handshake"
                                                  : "Could not negotiate quantum safe handshake"));
    if (result.summary)
        puts(result.summary);
    int code = result.outcome == NM_QUANTUM_OK ? 0 : result.outcome == NM_QUANTUM_NEGATIVE ? 1 : 2;
    nm_quantum_result_free(&result);
    freeaddrinfo(addresses);
    nm_quantum_tls_free(provider);
    return code;
}
