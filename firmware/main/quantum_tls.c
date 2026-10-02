#define _POSIX_C_SOURCE 200809L
#include "quantum_tls.h"
#include "nm_memory.h"
#include "endpoint_resource.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/oid_sum.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct nm_quantum_tls {
    WOLFSSL_CTX *context;
    unsigned char *trusted_pem;
    size_t trusted_pem_length;
};
static pthread_once_t library_once = PTHREAD_ONCE_INIT;
static int library_status;
static void initialize_library(void)
{
    library_status = wolfSSL_Init();
}

int64_t nm_quantum_now_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now))
        return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static WOLFSSL_CTX *new_context(const unsigned char *pem, size_t length)
{
    WOLFSSL_CTX *context = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!context)
        return NULL;
    if (wolfSSL_CTX_load_verify_buffer(context, pem, (long)length, WOLFSSL_FILETYPE_PEM) !=
        WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(context);
        return NULL;
    }
    wolfSSL_CTX_set_verify(context, WOLFSSL_VERIFY_PEER, NULL);
    return context;
}

nm_quantum_tls *nm_quantum_tls_new(const unsigned char *pem, size_t length)
{
    if (!pem || !length || length > LONG_MAX || pthread_once(&library_once, initialize_library) ||
        library_status != WOLFSSL_SUCCESS)
        return NULL;
    nm_quantum_tls *provider = nm_bulk_calloc(1, sizeof(*provider));
    if (!provider)
        return NULL;
    provider->trusted_pem = nm_bulk_malloc(length);
    if (provider->trusted_pem) {
        memcpy(provider->trusted_pem, pem, length);
        provider->trusted_pem_length = length;
        provider->context = new_context(pem, length);
    }
    if (!provider->context) {
        nm_quantum_tls_free(provider);
        return NULL;
    }
    return provider;
}

void nm_quantum_tls_free(nm_quantum_tls *provider)
{
    if (!provider)
        return;
    wolfSSL_CTX_free(provider->context);
    free(provider->trusted_pem);
    free(provider);
    /* Process-lifetime library state: never clean it up under another worker. */
}

void nm_quantum_result_free(nm_quantum_result *result)
{
    if (result) {
        free(result->summary);
        result->summary = NULL;
    }
}

/* 1 ready, 0 expired, -1 OS failure; never FD_SET an out-of-range descriptor. */
static int wait_socket(int fd, bool read_ready, int64_t deadline, const atomic_bool *cancellation)
{
#ifdef LWIP_SELECT_MAXNFDS
    const int limit = LWIP_SELECT_MAXNFDS;
#else
    const int limit = FD_SETSIZE;
#endif
    if (fd < 0 || fd >= limit) {
        errno = EMFILE;
        return -1;
    }
    for (;;) {
        if (cancellation && atomic_load(cancellation))
            return -2;
        int64_t now = nm_quantum_now_ms();
        if (now < 0) {
            errno = EIO;
            return -1;
        }
        int64_t remaining = deadline - now;
        if (remaining <= 0)
            return 0;
        if (cancellation && remaining > 100)
            remaining = 100;
        fd_set ready;
        FD_ZERO(&ready);
        FD_SET(fd, &ready);
        struct timeval wait = {.tv_sec = remaining / 1000, .tv_usec = (remaining % 1000) * 1000};
        int rc =
            select(fd + 1, read_ready ? &ready : NULL, read_ready ? NULL : &ready, NULL, &wait);
        if (rc < 0 && errno == EINTR)
            continue;
        if (!rc && cancellation)
            continue;
        return rc > 0 ? 1 : rc;
    }
}

static bool pq_oid(int oid)
{
    return oid == ML_DSA_44k || oid == ML_DSA_65k || oid == ML_DSA_87k;
}

/* Standard TLS group names shared with OpenSSL's group listing. wolfSSL's
 * native name differs for the three standalone ML-KEM groups only. */
static const char *group_name(WOLFSSL *ssl)
{
    const char *name = wolfSSL_get_curve_name(ssl);
    if (!name)
        return NULL;
    if (!strcmp(name, "ML_KEM_512"))
        return "MLKEM512";
    if (!strcmp(name, "ML_KEM_768"))
        return "MLKEM768";
    if (!strcmp(name, "ML_KEM_1024"))
        return "MLKEM1024";
    return name;
}

static const char *algorithm(int oid)
{
    switch (oid) {
    case ML_DSA_44k:
        return "ML-DSA-44";
    case ML_DSA_65k:
        return "ML-DSA-65";
    case ML_DSA_87k:
        return "ML-DSA-87";
    case RSAk:
        return "RSA";
    case ECDSAk:
        return "ECDSA";
    case CTC_SHA256wRSA:
        return "sha256WithRSAEncryption";
    case CTC_SHA384wRSA:
        return "sha384WithRSAEncryption";
    case CTC_SHA512wRSA:
        return "sha512WithRSAEncryption";
    case CTC_SHA256wECDSA:
        return "ecdsa-with-SHA256";
    case CTC_SHA384wECDSA:
        return "ecdsa-with-SHA384";
    case CTC_SHA512wECDSA:
        return "ecdsa-with-SHA512";
    default:
        return "classical/other";
    }
}

/* Observation-only callback. Errors do not suppress certificate classification.
 * This probe's private context prevents accepted untrusted intermediates from
 * entering any other probe's trust cache. Allocation failures still abort. */
static int observe_certificate_trust(int verified, WOLFSSL_X509_STORE_CTX *store)
{
    if (!store || !store->userCtx)
        return 0;
    if (!verified) {
        *(bool *)store->userCtx = false;
        if (store->error == MEMORY_E || store->error == MEMORY_ERROR)
            return 0;
    }
    return 1;
}

static char *certificate_summary(WOLFSSL_X509 *cert, WOLFSSL *ssl, bool safe, bool trusted)
{
    char *subject = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name(cert), NULL, 0);
    char *issuer = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(cert), NULL, 0);
    if (!subject || !issuer) {
        free(subject);
        free(issuer);
        return NULL;
    }
    int sig = wolfSSL_X509_get_signature_type(cert), key = wolfSSL_X509_get_pubkey_type(cert);
    int chain = wolfSSL_get_chain_count(wolfSSL_get_peer_chain(ssl));
    /* Public wolfSSL API returns a bounded DER UTCTime/GeneralizedTime value
     * owned by cert. Format this observation without newlib
     * or an OpenSSL compatibility layer. */
    char expires[11] = "unknown";
    const unsigned char *date = wolfSSL_X509_notAfter(cert);
    if (date && ((date[0] == 0x17 && date[1] == 13) || (date[0] == 0x18 && date[1] == 15))) {
        unsigned offset = date[0] == 0x17 ? 2 : 4;
        bool digits = true;
        for (unsigned i = 2; i < offset + 6; ++i)
            if (date[i] < '0' || date[i] > '9')
                digits = false;
        if (digits) {
            unsigned year = date[0] == 0x17 ? ((date[2] - '0') * 10 + date[3] - '0')
                                            : ((date[2] - '0') * 1000 + (date[3] - '0') * 100 +
                                               (date[4] - '0') * 10 + date[5] - '0');
            if (date[0] == 0x17)
                year += year < 50 ? 2000 : 1900;
            snprintf(expires, sizeof(expires), "%04u-%c%c-%c%c", year, date[offset + 2],
                     date[offset + 3], date[offset + 4], date[offset + 5]);
        }
    }
    const char *format = "Certificate PQC: %s (sig=%s, key=%s); SigAlg=%s; "
                         "KeyAlg=%s; Expires=%s; Subject=%s; Issuer=%s; ChainLength=%d%s";
    const char *trust_note = trusted ? "" : "; Certificate trust: not trusted";
    int size = snprintf(NULL, 0, format, safe ? "yes" : "no", pq_oid(sig) ? "yes" : "no",
                        pq_oid(key) ? "yes" : "no", algorithm(sig), algorithm(key), expires,
                        subject, issuer, chain, trust_note);
    char *summary = size >= 0 ? nm_bulk_malloc((size_t)size + 1) : NULL;
    if (summary)
        snprintf(summary, (size_t)size + 1, format, safe ? "yes" : "no", pq_oid(sig) ? "yes" : "no",
                 pq_oid(key) ? "yes" : "no", algorithm(sig), algorithm(key), expires, subject,
                 issuer, chain, trust_note);
    free(subject);
    free(issuer);
    return summary;
}

nm_quantum_result nm_quantum_tls_probe(nm_quantum_tls *provider, bool certificate, const char *host,
                                       const struct addrinfo *addresses, int64_t deadline)
{
    return nm_quantum_tls_probe_cancelable(provider, certificate, host, addresses, deadline, NULL);
}

nm_quantum_result nm_quantum_tls_probe_cancelable(nm_quantum_tls *provider, bool certificate,
                                                  const char *host,
                                                  const struct addrinfo *addresses,
                                                  int64_t deadline, const atomic_bool *cancellation)
{
    return nm_quantum_tls_probe_group(provider, certificate, host, addresses, deadline,
                                      cancellation, NULL);
}

nm_quantum_result nm_quantum_tls_probe_group(nm_quantum_tls *provider, bool certificate,
                                             const char *host, const struct addrinfo *addresses,
                                             int64_t deadline, const atomic_bool *cancellation,
                                             const char *requested_group)
{
    nm_quantum_result result = {.outcome = NM_QUANTUM_ERROR, .certificate_trusted = true};
    WOLFSSL_CTX *observation_context = NULL;
    WOLFSSL *ssl = NULL;
    WOLFSSL_X509 *cert = NULL;
    int fd = -1;
    if (!provider || !host || !*host || strlen(host) > 253 || !addresses)
        return result;
    if (certificate) {
        observation_context = new_context(provider->trusted_pem, provider->trusted_pem_length);
        if (!observation_context) {
            result.outcome = NM_QUANTUM_LOCAL_FAILURE;
            goto cleanup;
        }
    }
    ssl = wolfSSL_new(certificate ? observation_context : provider->context);
    if (!ssl) {
        result.outcome = NM_QUANTUM_LOCAL_FAILURE;
        goto cleanup;
    }
    unsigned char ip[16];
    bool numeric = inet_pton(AF_INET, host, ip) == 1 || inet_pton(AF_INET6, host, ip) == 1;
    /* .NET quantumcert classifies the received certificate independently of
     * trust/expiry/name errors. Record trust as an informational note, accepting
     * verification errors only in this probe's isolated observation context. */
    if (certificate) {
        wolfSSL_SetCertCbCtx(ssl, &result.certificate_trusted);
        wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER, observe_certificate_trust);
    }
    if ((!certificate && (numeric ? wolfSSL_check_ip_address(ssl, host)
                                  : wolfSSL_check_domain_name(ssl, host)) != WOLFSSL_SUCCESS) ||
        (!numeric && wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host,
                                    (unsigned short)strlen(host)) != WOLFSSL_SUCCESS)) {
        result.outcome = NM_QUANTUM_LOCAL_FAILURE;
        goto cleanup;
    }
    int groups[] = {WOLFSSL_X25519MLKEM768, WOLFSSL_SECP256R1MLKEM768, WOLFSSL_SECP384R1MLKEM1024,
                    WOLFSSL_ML_KEM_512,     WOLFSSL_ML_KEM_768,        WOLFSSL_ML_KEM_1024,
                    WOLFSSL_ECC_X25519,     WOLFSSL_ECC_SECP256R1};
    int selected[8];
    size_t selected_count = 0;
    if (requested_group) {
        static const char *const names[] = {
            "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
            "MLKEM512",       "MLKEM768",          "MLKEM1024",
            "X25519",         "secp256r1"};
        if (strlen(requested_group) > 511)
            goto cleanup;
        char copy[512];
        memcpy(copy, requested_group, strlen(requested_group) + 1);
        char *cursor = copy, *next;
        do {
            next = strchr(cursor, ':');
            if (next)
                *next++ = 0;
            int id = 0;
            for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
                if (!strcmp(cursor, names[i]))
                    id = groups[i];
            if (!id || selected_count == 8) {
                selected_count = 0;
                break;
            }
            selected[selected_count++] = id;
            cursor = next;
        } while (cursor);
        if (!selected_count) {
            snprintf(result.error_message, sizeof(result.error_message),
                     "Unsupported TLS group: %.64s", requested_group);
            goto cleanup;
        }
    }
    if (wolfSSL_set_groups(ssl, requested_group ? selected : groups,
                           requested_group ? (int)selected_count
                           : certificate   ? 8
                                           : 6) != WOLFSSL_SUCCESS) {
        result.outcome = NM_QUANTUM_LOCAL_FAILURE;
        goto cleanup;
    }
    for (const struct addrinfo *a = addresses; a; a = a->ai_next) {
        if (cancellation && atomic_load(cancellation)) {
            result.outcome = NM_QUANTUM_CANCELLED;
            goto cleanup;
        }
        if (nm_quantum_now_ms() >= deadline) {
            result.outcome = NM_QUANTUM_TIMEOUT;
            goto cleanup;
        }
        fd = socket(a->ai_family, SOCK_STREAM, a->ai_protocol);
        if (fd < 0) {
            result.error = errno;
            result.socket_error = true;
            if (nm_endpoint_resource_errno(errno))
                goto cleanup;
            continue;
        }
#ifdef LWIP_SELECT_MAXNFDS
        const int select_limit = LWIP_SELECT_MAXNFDS;
#else
        const int select_limit = FD_SETSIZE;
#endif
        if (fd >= select_limit) {
            result.error = EMFILE;
            result.socket_error = true;
            goto cleanup;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
            goto next;
        int rc = connect(fd, a->ai_addr, a->ai_addrlen);
        if (rc && errno != EINPROGRESS && errno != EWOULDBLOCK)
            goto next;
        if (rc) {
            rc = wait_socket(fd, false, deadline, cancellation);
            if (rc == -2) {
                result.outcome = NM_QUANTUM_CANCELLED;
                goto cleanup;
            }
            if (!rc) {
                result.outcome = NM_QUANTUM_TIMEOUT;
                goto cleanup;
            }
            if (rc < 0)
                goto next;
        }
        int error = 0;
        socklen_t length = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) || error) {
            if (error)
                errno = error;
            goto next;
        }
        break;
    next:
        result.error = errno;
        result.socket_error = true;
        close(fd);
        fd = -1;
        if (nm_endpoint_resource_errno(result.error))
            goto cleanup;
    }
    if (fd < 0 || wolfSSL_set_fd(ssl, fd) != WOLFSSL_SUCCESS)
        goto cleanup;
    result.error = 0;
    result.socket_error = false;
    for (;;) {
        if (cancellation && atomic_load(cancellation)) {
            result.outcome = NM_QUANTUM_CANCELLED;
            goto cleanup;
        }
        if (nm_quantum_now_ms() >= deadline) {
            result.outcome = NM_QUANTUM_TIMEOUT;
            goto cleanup;
        }
        errno = 0;
        int rc = wolfSSL_connect(ssl);
        if (nm_quantum_now_ms() >= deadline) {
            result.outcome = NM_QUANTUM_TIMEOUT;
            goto cleanup;
        }
        if (rc == WOLFSSL_SUCCESS)
            break;
        int error = wolfSSL_get_error(ssl, rc);
        if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE) {
            result.error = error;
            if (error == MEMORY_E || error == MEMORY_ERROR || nm_endpoint_resource_errno(errno))
                result.outcome = NM_QUANTUM_LOCAL_FAILURE;
            goto cleanup;
        }
        rc = wait_socket(fd, error == WOLFSSL_ERROR_WANT_READ, deadline, cancellation);
        if (rc == -2) {
            result.outcome = NM_QUANTUM_CANCELLED;
            goto cleanup;
        }
        if (rc <= 0) {
            result.error = rc < 0 ? errno : 0;
            result.socket_error = rc < 0;
            result.outcome = rc == 0 ? NM_QUANTUM_TIMEOUT : NM_QUANTUM_ERROR;
            goto cleanup;
        }
    }
    /* Earlier address attempts may fail before a successful IPv4/IPv6 fallback. */
    result.error = 0;
    result.socket_error = false;
    const char *group = group_name(ssl);
    const char *protocol = wolfSSL_get_version(ssl), *cipher = wolfSSL_get_cipher(ssl);
    snprintf(result.protocol, sizeof(result.protocol), "%s", protocol ? protocol : "unknown");
    snprintf(result.cipher, sizeof(result.cipher), "%s", cipher ? cipher : "unknown");
    if (group) {
        int length = snprintf(result.group, sizeof(result.group), "%s", group);
        if (length < 0 || (size_t)length >= sizeof(result.group))
            goto cleanup;
    }
    bool safe;
    if (certificate) {
        cert = wolfSSL_get_peer_certificate(ssl);
        if (!cert) {
            result.outcome = NM_QUANTUM_LOCAL_FAILURE;
            goto cleanup;
        }
        result.signature_oid = wolfSSL_X509_get_signature_type(cert);
        result.key_oid = wolfSSL_X509_get_pubkey_type(cert);
        snprintf(result.signature_algorithm, sizeof(result.signature_algorithm), "%s",
                 algorithm(result.signature_oid));
        snprintf(result.key_algorithm, sizeof(result.key_algorithm), "%s",
                 algorithm(result.key_oid));
        safe = pq_oid(result.signature_oid) || pq_oid(result.key_oid);
        result.summary = certificate_summary(cert, ssl, safe, result.certificate_trusted);
        if (!result.summary) {
            result.outcome = NM_QUANTUM_LOCAL_FAILURE;
            goto cleanup;
        }
    } else
        safe = group && (strstr(group, "MLKEM") || strstr(group, "ML_KEM"));
    result.outcome = safe ? NM_QUANTUM_OK : NM_QUANTUM_NEGATIVE;
cleanup:
    /* Preserve negotiated-group evidence even if certificate verification fails.
     * It is diagnostic only: success still requires the authenticated handshake. */
    if (ssl && !result.group[0]) {
        const char *negotiated = group_name(ssl);
        if (negotiated)
            snprintf(result.group, sizeof(result.group), "%s", negotiated);
    }
    if (result.error) {
        if (result.socket_error)
            snprintf(result.error_message, sizeof(result.error_message), "%s",
                     strerror(result.error));
        else
            wolfSSL_ERR_error_string_n((unsigned long)result.error, result.error_message,
                                       sizeof(result.error_message));
    }
    if (result.outcome == NM_QUANTUM_ERROR && result.socket_error &&
        nm_endpoint_resource_errno(result.error))
        result.outcome = NM_QUANTUM_LOCAL_FAILURE;
    wolfSSL_X509_free(cert);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(observation_context);
    if (fd >= 0)
        close(fd);
    return result;
}
