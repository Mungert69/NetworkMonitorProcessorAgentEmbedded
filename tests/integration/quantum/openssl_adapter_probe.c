/* Host boundary only: real production CLI parser/runner and wolfSSL TCP/TLS.
 * libc DNS replaces ESP's bounded resolver here, never in production firmware. */
#define _POSIX_C_SOURCE 200809L
#include "openssl_cmd_processor.h"
#include "tls_inspection.h"
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static nm_quantum_tls *provider;
nm_tls_inspection nm_tls_inspect(const nm_tls_inspection_request *r)
{
    int64_t start = nm_quantum_now_ms();
    char port[8];
    snprintf(port, sizeof(port), "%u", r->port);
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM, .ai_family = AF_UNSPEC};
    struct addrinfo *addresses = NULL;
    if (getaddrinfo(r->connect_host ? r->connect_host : r->host, port, &hints, &addresses))
        return (nm_tls_inspection){.observation.outcome = NM_QUANTUM_ERROR};
    nm_quantum_result result = nm_quantum_tls_probe_options(
        provider, r->mode == NM_TLS_INSPECT_CERTIFICATE, r->host, addresses, start + r->timeout_ms,
        r->cancellation, r->group, r->diagnostics);
    freeaddrinfo(addresses);
    return (nm_tls_inspection){.observation = result,
                               .elapsed_ms = (unsigned)(nm_quantum_now_ms() - start)};
}
void nm_tls_inspection_release(nm_tls_inspection *result)
{
    nm_quantum_result_free(&result->observation);
}
int main(int argc, char **argv)
{
    if (argc != 3)
        return 2;
    FILE *file = fopen(argv[1], "rb");
    if (!file)
        return 2;
    unsigned char pem[65536];
    size_t length = fread(pem, 1, sizeof(pem), file);
    bool valid = length && !ferror(file) && feof(file);
    fclose(file);
    provider = valid ? nm_quantum_tls_new(pem, length) : NULL;
    if (!provider)
        return 2;
    nm_openssl_command request;
    const char *error;
    if (!nm_openssl_cmd_parse(argv[2], &request, &error)) {
        fprintf(stderr, "%s\n", error);
        nm_quantum_tls_free(provider);
        return 2;
    }
    request.timeout_ms = 2000;
    nm_cmd_result result = nm_openssl_cmd_run(&request, NULL);
    if (result.output)
        puts(result.output);
    int code = result.success ? 0 : 1;
    free(result.output);
    nm_quantum_tls_free(provider);
    return code;
}
