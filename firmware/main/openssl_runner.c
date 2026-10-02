#include "openssl_runner.h"
#include <ctype.h>
#include <string.h>

const char *nm_openssl_ciphers(void)
{
    return "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
}
const char *nm_openssl_tls12_ciphers(void)
{
    return "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
           "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384";
}
static bool cipher_list_valid(const char *list, const char *supported)
{
    if (!list || !*list || strlen(list) >= 512)
        return false;
    const char *p = list;
    do {
        const char *end = strchr(p, ':');
        size_t length = end ? (size_t)(end - p) : strlen(p);
        bool found = false;
        for (const char *s = supported; s;) {
            const char *last = strchr(s, ':');
            size_t n = last ? (size_t)(last - s) : strlen(s);
            if (length && length == n && !memcmp(p, s, n))
                found = true;
            s = last ? last + 1 : NULL;
        }
        if (!found)
            return false;
        p = end ? end + 1 : NULL;
    } while (p);
    return true;
}
bool nm_openssl_ciphers_valid(const char *list)
{
    return cipher_list_valid(list, nm_openssl_ciphers());
}
bool nm_openssl_tls12_ciphers_valid(const char *list)
{
    return cipher_list_valid(list, nm_openssl_tls12_ciphers());
}
const char *nm_openssl_cipher_name(const char *name)
{
    static const char *const mapping[][2] = {
        {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256"},
        {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384"},
        {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"},
        {"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384"}};
    if (!name)
        return NULL;
    for (size_t i = 0; i < sizeof(mapping) / sizeof(*mapping); ++i)
        if (!strcmp(name, mapping[i][0]))
            return mapping[i][1];
    return name;
}

static const char *const groups[] = {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
                                     "MLKEM512",       "MLKEM768",          "MLKEM1024",
                                     "X25519",         "secp256r1",         "secp384r1",
                                     "secp521r1"};

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
    if (!strcmp(key, "prime256v1") || !strcmp(key, "p256"))
        return "secp256r1";
    if (!strcmp(key, "p384"))
        return "secp384r1";
    if (!strcmp(key, "p521"))
        return "secp521r1";
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
    if (request->diagnostics && request->diagnostics->ciphersuites &&
        !(request->diagnostics->tls_version == 12
              ? nm_openssl_tls12_ciphers_valid(request->diagnostics->ciphersuites)
              : nm_openssl_ciphers_valid(request->diagnostics->ciphersuites))) {
        nm_tls_inspection invalid = {.observation.outcome = NM_QUANTUM_ERROR};
        strcpy(invalid.observation.error_message, "Unsupported TLS cipher suite");
        return invalid;
    }
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
                if (!name ||
                    (request->diagnostics && request->diagnostics->tls_version == 12 &&
                     strstr(name, "MLKEM")) ||
                    ++count > 16 || strlen(name) + length + 2 > sizeof(group_list)) {
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
        .connect_host = request->connect_host,
        .diagnostics = request->diagnostics};
    return nm_tls_inspect(&inspection);
}
