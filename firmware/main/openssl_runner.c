#include "openssl_runner.h"
#include <ctype.h>
#include <string.h>

static const char *const groups[] = {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
                                     "MLKEM512",       "MLKEM768",          "MLKEM1024",
                                     "X25519",         "secp256r1"};

/* Normalize punctuation/case, not cryptographic parameters. In particular
 * Kyber draft groups and unsupported hybrid combinations are not aliases. */
static bool normalized(const char *input, char output[64])
{
    if (!input || strlen(input) > 128)
        return false;
    size_t n = 0;
    for (; *input; ++input) {
        unsigned char c = (unsigned char)*input;
        if (c == '_' || c == '-')
            continue;
        if (!isalnum(c) || n + 1 >= 64)
            return false;
        output[n++] = (char)tolower(c);
    }
    output[n] = 0;
    return n != 0;
}

const char *nm_openssl_group_name(const char *name)
{
    char key[64], candidate[64];
    if (!normalized(name, key))
        return NULL;
    for (size_t i = 0; i < nm_openssl_group_count(); ++i) {
        if (normalized(groups[i], candidate) && !strcmp(candidate, key))
            return groups[i];
    }
    return NULL;
}
size_t nm_openssl_group_count(void)
{
    return sizeof(groups) / sizeof(groups[0]);
}
const char *nm_openssl_group_at(size_t index)
{
    return index < nm_openssl_group_count() ? groups[index] : NULL;
}
nm_tls_inspection nm_openssl_execute(const nm_openssl_request *request)
{
    if (!request)
        return (nm_tls_inspection){.observation.outcome = NM_QUANTUM_ERROR};
    char group_list[512] = "";
    bool valid = true;
    if (request->group) {
        if (strlen(request->group) >= sizeof(group_list))
            valid = false;
        else {
            char copy[512];
            memcpy(copy, request->group, strlen(request->group) + 1);
            char *cursor = copy, *next;
            size_t length = 0, count = 0;
            do {
                next = strchr(cursor, ':');
                if (next)
                    *next++ = 0;
                const char *name = nm_openssl_group_name(cursor);
                if (!name || ++count > 8 || strlen(name) + length + 2 > sizeof(group_list)) {
                    valid = false;
                    break;
                }
                if (length)
                    group_list[length++] = ':';
                memcpy(group_list + length, name, strlen(name) + 1);
                length += strlen(name);
                cursor = next;
            } while (cursor);
        }
    }
    if (!valid) {
        nm_tls_inspection result = {.observation.outcome = NM_QUANTUM_ERROR};
        memcpy(result.observation.error_message, "Unsupported TLS group",
               sizeof("Unsupported TLS group"));
        return result;
    }
    nm_tls_inspection_request inspection = {
        .host = request->host,
        .port = request->port,
        .timeout_ms = request->timeout_ms,
        .mode = request->show_certificates ? NM_TLS_INSPECT_CERTIFICATE : NM_TLS_INSPECT_HANDSHAKE,
        .cancellation = request->cancellation,
        .group = request->group ? group_list : NULL,
        .connect_host = request->connect_host};
    return nm_tls_inspect(&inspection);
}
