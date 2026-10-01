#include "command_security.h"
#include "nm_command_limits.h"
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

/* JSON grammar/UTF-8/depth are validated by nm_json_read first. These spans
 * preserve the sender's bytes, including .NET escaping and numeric formatting.
 * Never reserialize a parsed object to manufacture bytes for verification. */
typedef struct {
    const char *start;
    size_t length;
} span;

static const char *whitespace(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\r' || *p == '\n' || *p == '\t'))
        ++p;
    return p;
}

static const char *value_end(const char *p, const char *end)
{
    bool quoted = false, escaped = false;
    unsigned depth = 0;
    for (; p < end; ++p) {
        char c = *p;
        if (quoted) {
            if (escaped)
                escaped = false;
            else if (c == '\\')
                escaped = true;
            else if (c == '"') {
                quoted = false;
                if (!depth)
                    return p + 1;
            }
        } else if (c == '"')
            quoted = true;
        else if (c == '{' || c == '[')
            ++depth;
        else if (c == '}' || c == ']') {
            if (!depth)
                return p;
            if (!--depth)
                return p + 1;
        } else if (!depth &&
                   (c == ',' || c == ':' || c == ' ' || c == '\r' || c == '\n' || c == '\t'))
            return p;
    }
    return p;
}

static bool field(span object, const char *name, span *result)
{
    const char *end = object.start + object.length;
    const char *p = whitespace(object.start, end);
    if (p == end || *p++ != '{')
        return false;
    bool found = false;
    for (;;) {
        p = whitespace(p, end);
        if (p == end || *p == '}')
            return found;
        const char *key = p;
        if (*p != '"')
            return false;
        p = value_end(p, end);
        size_t key_length = (size_t)(p - key);
        bool match = key_length == strlen(name) + 2 && !memcmp(key + 1, name, key_length - 2);
        p = whitespace(p, end);
        if (p == end || *p++ != ':')
            return false;
        p = whitespace(p, end);
        const char *start = p;
        p = value_end(p, end);
        if (p <= start)
            return false;
        if (match) {
            if (found)
                return false;
            *result = (span){start, (size_t)(p - start)};
            found = true;
        }
        p = whitespace(p, end);
        if (p == end || *p == '}')
            return found;
        if (*p++ != ',')
            return false;
    }
}

static bool unique_field(yyjson_mut_val *object, const char *name)
{
    size_t i, n;
    yyjson_mut_val *key, *value;
    unsigned matches = 0;
    yyjson_mut_obj_foreach(object, i, n, key, value)
    {
        (void)value;
        if (yyjson_mut_equals_str(key, name))
            ++matches;
    }
    return matches == 1;
}

static unsigned char *pack(const char *operation, const char *target, span object, span signature,
                           size_t *length)
{
    size_t operation_size = strlen(operation), target_size = strlen(target);
    if (signature.length < 2 || signature.length > object.length ||
        signature.start < object.start ||
        (size_t)(signature.start - object.start) > object.length - signature.length)
        return NULL;
    size_t json_size = object.length - signature.length + 2;
    if (operation_size > NM_ESP_MAX_SIGNED_PAYLOAD || target_size > NM_ESP_MAX_SIGNED_PAYLOAD ||
        json_size > NM_ESP_MAX_SIGNED_PAYLOAD ||
        operation_size + target_size + json_size + 12 > NM_ESP_MAX_SIGNED_PAYLOAD)
        return NULL;
    *length = operation_size + target_size + json_size + 12;
    unsigned char *out = nm_bulk_malloc(*length);
    if (!out)
        return NULL;
    size_t offset = 0;
    size_t sizes[] = {operation_size, target_size, json_size};
    for (unsigned i = 0; i < 3; ++i) {
        uint32_t n = (uint32_t)sizes[i];
        out[offset++] = (unsigned char)(n >> 24);
        out[offset++] = (unsigned char)(n >> 16);
        out[offset++] = (unsigned char)(n >> 8);
        out[offset++] = (unsigned char)n;
        if (i < 2)
            memcpy(out + offset, i ? target : operation, sizes[i]);
        else {
            size_t prefix = (size_t)(signature.start - object.start);
            memcpy(out + offset, object.start, prefix);
            memcpy(out + offset + prefix, "\"\"", 2);
            memcpy(out + offset + prefix + 2, signature.start + signature.length,
                   object.length - prefix - signature.length);
        }
        offset += sizes[i];
    }
    return out;
}

yyjson_mut_doc *nm_command_verify_mldsa_event(const char *message, size_t message_length,
                                              const char *operation, const char *target,
                                              const unsigned char *public_key,
                                              size_t public_key_length)
{
    if (!message || !message_length || message_length > NM_ESP_MAX_COMMAND || !operation ||
        !target || !public_key || !public_key_length || public_key_length > 4096)
        return NULL;
    yyjson_mut_doc *event_doc = nm_json_read(message, message_length);
    yyjson_mut_val *event = yyjson_mut_doc_get_root(event_doc);
    yyjson_mut_val *data = yyjson_mut_obj_get(event, "data");
    yyjson_mut_val *signature = yyjson_mut_obj_get(data, "BackendSignature");
    span object = {0}, signature_span = {0};
    yyjson_mut_doc *result = NULL;
    unsigned char *payload = NULL, *sig = NULL;
    wc_MlDsaKey *key = NULL;
    DerBuffer *der = NULL;
    bool initialized = false;
    if (!yyjson_mut_is_obj(event) || !yyjson_mut_is_obj(data) || !unique_field(event, "data") ||
        !unique_field(data, "BackendSignature") || !yyjson_mut_is_str(signature) ||
        yyjson_mut_get_len(signature) != 4412 ||
        !field((span){message, message_length}, "data", &object) ||
        !field(object, "BackendSignature", &signature_span))
        goto done;
    size_t payload_size = 0;
    word32 sig_size = WC_MLDSA_65_SIG_SIZE;
    payload = pack(operation, target, object, signature_span, &payload_size);
    sig = nm_bulk_malloc(WC_MLDSA_65_SIG_SIZE);
    key = nm_bulk_calloc(1, sizeof(*key));
    if (!payload || !sig || !key ||
        Base64_Decode((const unsigned char *)yyjson_mut_get_str(signature),
                      (word32)yyjson_mut_get_len(signature), sig, &sig_size) ||
        sig_size != WC_MLDSA_65_SIG_SIZE || wc_MlDsaKey_Init(key, NULL, INVALID_DEVID))
        goto done;
    initialized = true;
    word32 index = 0;
    byte level = 0;
    int verified = 0;
    if (wc_PemToDer(public_key, (long)public_key_length, PUBLICKEY_TYPE, &der, NULL, NULL, NULL) ||
        !der || wc_MlDsaKey_PublicKeyDecode(key, der->buffer, der->length, &index) ||
        index != der->length || wc_MlDsaKey_GetParams(key, &level) || level != WC_ML_DSA_65 ||
        wc_MlDsaKey_VerifyCtx(key, sig, (word32)sig_size, NULL, 0, payload, (word32)payload_size,
                              &verified) ||
        verified != 1)
        goto done;
    /* Return the exact authenticated object. The signature field is public and
     * remains present, matching the .NET object; consumers ignore it. */
    result = nm_json_read(object.start, object.length);
done:
    if (initialized)
        wc_MlDsaKey_Free(key);
    wc_FreeDer(&der);
    free(key);
    free(sig);
    free(payload);
    yyjson_mut_doc_free(event_doc);
    return result;
}
