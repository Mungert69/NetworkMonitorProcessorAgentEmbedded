#include "command_security.h"
#include "nm_command_limits.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/base64.h"
#include "mbedtls/pk.h"
#include "psa/crypto.h"

static int sha256_bytes(const unsigned char *input, size_t length, unsigned char digest[32])
{
    size_t digest_length = 0;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, input, length,
                                           digest, 32, &digest_length);
    return status == PSA_SUCCESS && digest_length == 32 ? 0 : -1;
}

/* Parity-tested against MessageSecurityPolicyRegistry.RequiresProcessorSignature.
 * AuthKey has a separate verifier in .NET; OTA is specific to C processors. */
bool nm_command_requires_signature(const char *operation)
{
    static const char *const protected[] = {
        "getCmdProcessorSource", "getCmdProcessorHelp", "getCmdProcessorList",
        "deleteCmdProcessor", "addCmdProcessor", "processorCommand",
        "processorQueueDic", "processorScan", "cancelCommand", "getConnectSource",
        "getConnectList", "deleteConnect", "addConnect", "processorInit",
        "processorAuthKey", "processorFirmwareUpdate", "processorFirmwareHealthAck"
    };
    if (!operation) return false;
    for (size_t i = 0; i < sizeof(protected) / sizeof(protected[0]); ++i)
        if (!strcmp(operation, protected[i])) return true;
    return false;
}

static bool part(const unsigned char **cursor, size_t *remaining,
                 const unsigned char **value, size_t *length)
{
    if (*remaining < 4) return false;
    const unsigned char *p = *cursor;
    uint32_t n = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                 ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    if (n > *remaining - 4) return false;
    *value = p + 4;
    *length = n;
    *cursor += 4 + n;
    *remaining -= 4 + n;
    return true;
}

static bool unique_fields(yyjson_mut_val *object)
{
    unsigned mask = 0;
    size_t index, count;
    yyjson_mut_val *key, *item;
    yyjson_mut_obj_foreach(object, index, count, key, item) {
        unsigned flag = yyjson_mut_equals_str(key, "Version") ? 1 :
                        yyjson_mut_equals_str(key, "Algorithm") ? 2 :
                        yyjson_mut_equals_str(key, "Payload") ? 4 :
                        yyjson_mut_equals_str(key, "Signature") ? 8 : 0;
        if (!flag || (mask & flag)) return false;
        mask |= flag;
    }
    return mask == 15;
}

yyjson_mut_doc *nm_command_verify(yyjson_mut_val *envelope, const char *operation,
                         const char *target, const unsigned char *public_key,
                         size_t public_key_length)
{
    if (!operation || !target || !public_key || !public_key_length ||
        !yyjson_mut_is_obj(envelope) || !unique_fields(envelope)) return NULL;
    yyjson_mut_val *version = yyjson_mut_obj_get(envelope, "Version");
    yyjson_mut_val *algorithm = yyjson_mut_obj_get(envelope, "Algorithm");
    yyjson_mut_val *payload = yyjson_mut_obj_get(envelope, "Payload");
    yyjson_mut_val *signature = yyjson_mut_obj_get(envelope, "Signature");
    if (!yyjson_mut_is_uint(version) || yyjson_mut_get_uint(version) != 1 ||
        !yyjson_mut_is_str(algorithm) || strcmp(yyjson_mut_get_str(algorithm), "ES256") ||
        !yyjson_mut_is_str(payload) || !yyjson_mut_is_str(signature)) return NULL;
    size_t encoded_length = strlen(yyjson_mut_get_str(payload)), signature_length = strlen(yyjson_mut_get_str(signature));
    if (!encoded_length || encoded_length > 4 * ((NM_ESP_MAX_SIGNED_PAYLOAD + 2) / 3) ||
        !signature_length || signature_length > 108) return NULL;
    unsigned char *decoded = nm_bulk_malloc(NM_ESP_MAX_SIGNED_PAYLOAD + 1);
    if (!decoded) return NULL;
    unsigned char sig[80], digest[32];
    size_t decoded_length = 0, sig_length = 0;
    yyjson_mut_doc *result = NULL;
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    if (mbedtls_base64_decode(decoded, NM_ESP_MAX_SIGNED_PAYLOAD, &decoded_length,
            (const unsigned char *)yyjson_mut_get_str(payload), encoded_length) ||
        mbedtls_base64_decode(sig, sizeof(sig), &sig_length,
            (const unsigned char *)yyjson_mut_get_str(signature), signature_length) ||
        mbedtls_pk_parse_public_key(&key, public_key, public_key_length) ||
        !mbedtls_pk_can_do_psa(&key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                              PSA_KEY_USAGE_VERIFY_HASH) || mbedtls_pk_get_bitlen(&key) != 256 ||
        sha256_bytes(decoded, decoded_length, digest) ||
        mbedtls_pk_verify(&key, MBEDTLS_MD_SHA256, digest, sizeof(digest), sig, sig_length)) goto done;
    const unsigned char *cursor = decoded, *value;
    size_t remaining = decoded_length, length;
    if (!part(&cursor, &remaining, &value, &length) || length != strlen(operation) ||
        memcmp(value, operation, length)) goto done;
    if (!part(&cursor, &remaining, &value, &length) || length != strlen(target) ||
        memcmp(value, target, length)) goto done;
    if (!part(&cursor, &remaining, &value, &length) || remaining ||
        memchr(value, 0, length)) goto done;
    // Parse the authenticated bytes only, requiring the complete JSON document.
    decoded[decoded_length] = 0;
    result = nm_json_read((const char *)value, length);
    if (!yyjson_mut_is_obj(yyjson_mut_doc_get_root(result))) { yyjson_mut_doc_free(result); result = NULL; }
done:
    mbedtls_pk_free(&key);
    free(decoded);
    return result;
}
