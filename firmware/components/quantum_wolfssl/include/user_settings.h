#ifndef NM_WOLFSSL_TRIAL_SETTINGS_H
#define NM_WOLFSSL_TRIAL_SETTINGS_H
/* Quantum endpoint TLS and ML-DSA command verification. MQTT/HTTP/OTA TLS stays mbedTLS. */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define WC_RSA_PSS
#define HAVE_SNI
#define WOLFSSL_IP_ALT_NAME
#define HAVE_ECC
#define HAVE_ECC384
#define HAVE_ECC521
#define HAVE_CURVE25519
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_PQC_HYBRIDS
#define WOLFSSL_HAVE_MLDSA
#define WOLFSSL_MLDSA_VERIFY_ONLY
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define HAVE_AESGCM
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_ASN_TEMPLATE
#define KEEP_PEER_CERT
#define SESSION_CERTS
/* Public servers commonly send cross-signed roots. Build the verified path to
 * a configured trust anchor, rather than requiring every extra certificate's
 * issuer to be another configured root. Leaf authentication remains required. */
#define WOLFSSL_ALT_CERT_CHAINS
/* Each probe is fresh; retaining PQ certificate chains in the global session
 * cache would reserve megabytes of internal BSS. No resumption/cache needed. */
#define NO_SESSION_CACHE
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS
#define NO_DH
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_PSK
#define NO_PWDBASED
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#ifndef WOLFSSL_IGNORE_FILE_WARN
#define WOLFSSL_IGNORE_FILE_WARN
#endif
#ifdef ESP_PLATFORM
#include "esp_random.h"
#include "nm_memory.h"
#define XMALLOC_OVERRIDE
#define XMALLOC(s, h, t) ((void)(h), (void)(t), nm_bulk_malloc(s))
#define XFREE(p, h, t) ((void)(h), (void)(t), free(p))
#define XREALLOC(p, s, h, t) ((void)(h), (void)(t), nm_bulk_realloc(p, s))
static inline int nm_quantum_random(unsigned char *out, unsigned int size)
{
    /* Hardware RNG requires active Wi-Fi/Bluetooth entropy, as in the agent. */
    esp_fill_random(out, size);
    return 0;
}
#define CUSTOM_RAND_GENERATE_BLOCK nm_quantum_random
#define WOLFSSL_NO_FILESYSTEM
#endif
#endif
