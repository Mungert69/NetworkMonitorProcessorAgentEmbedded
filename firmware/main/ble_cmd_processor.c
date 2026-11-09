#include "ble_cmd_processor.h"
#include "ble_buffer.h"
#include "ble_payload.h"
#include "ble_metric.h"
#include "cmd_arguments.h"
#include "cmd_output.h"
#include "nm_memory.h"
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

const char *nm_ble_cmd_help(bool listen)
{
    return listen ? "BLE passive listen\nUsage: [--payload raw|manufacturer|service] "
                    "[--manufacturer_id ID] [--service_uuid UUID] [--raw_payload HEX]\n"
                    "Reads all retained advertisements in the completed snapshot. Legacy key, "
                    "format, nonce_len, tag_len, nonce_at and max_captures are ignored.\n"
                  : "BLE broadcast decode\nUsage: --address MAC [--format "
                    "raw|aesgcm|aesctr|victron|ruuvi|bthome] "
                    "[--key KEY] [--payload raw|manufacturer|service] [--manufacturer_id ID] "
                    "[--service_uuid UUID] [--metric NAME] [--raw_payload HEX] "
                    "[--nonce_len 1..16] [--tag_len 12..16] [--nonce_at start|end]\n"
                    "Uses the last 70 seconds of the completed snapshot. "
                    "metric_scale/metric_offset are accepted legacy options.\n";
}
static bool copy_text(char *dst, size_t capacity, const char *src)
{
    if (strlen(src) >= capacity)
        return false;
    memcpy(dst, src, strlen(src) + 1);
    return true;
}
static void lower(char *text)
{
    for (; *text; ++text)
        *text = (char)tolower((unsigned char)*text);
}
static bool integer(const char *text, long minimum, long maximum, long *out)
{
    char *end;
    errno = 0;
    long n = strtol(text, &end, !strncasecmp(text, "0x", 2) ? 16 : 10);
    if (errno || end == text || *end || n < minimum || n > maximum)
        return false;
    *out = n;
    return true;
}
bool nm_ble_cmd_parse(const char *arguments, bool listen, nm_ble_command *r, const char **error)
{
    if (!r || !error)
        return false;
    *error = "Invalid or oversized BLE command option";
    *r = (nm_ble_command){
        .listen = listen, .company = -1, .nonce_length = 12, .tag_length = 16, .timeout_ms = 70000};
    strcpy(r->format, "aesgcm");
    strcpy(r->payload, listen ? "raw" : "manufacturer");
    strcpy(r->metric, "pv_power");
    if (!arguments || strlen(arguments) > 4096)
        return false;
    const char *cursor = arguments;
    char token[600], value[520];
    bool payload_set = false, company_set = false, service_set = false;
    while (true) {
        if (!nm_cmd_argument_token(&cursor, token, sizeof(token)))
            return false;
        if (!*token)
            break;
        if (strncmp(token, "--", 2))
            return false;
        char *name = token + 2, *eq = strchr(name, '=');
        if (eq) {
            *eq++ = 0;
            if (!copy_text(value, sizeof(value), eq))
                return false;
        } else if (!nm_cmd_argument_token(&cursor, value, sizeof(value)) || !*value ||
                   !strncmp(value, "--", 2))
            return false;
        long number;
        if (!strcasecmp(name, "payload")) {
            if (!copy_text(r->payload, sizeof(r->payload), value))
                return false;
            payload_set = true;
        } else if (!strcasecmp(name, "manufacturer_id")) {
            if (!integer(value, -1, 65535, &number))
                return false;
            r->company = (int)number;
            company_set = true;
        } else if (!strcasecmp(name, "service_uuid")) {
            if (!nm_ble_payload_parse_service_uuid(value, r->uuid, &r->uuid_length))
                return false;
            service_set = true;
        } else if (!strcasecmp(name, "raw_payload")) {
            if (!nm_ble_payload_parse_hex_payload(value, r->raw, &r->raw_length))
                return false;
            r->injected = true;
        } else if (listen && (!strcasecmp(name, "key") || !strcasecmp(name, "format") ||
                              !strcasecmp(name, "nonce_len") || !strcasecmp(name, "tag_len") ||
                              !strcasecmp(name, "nonce_at") || !strcasecmp(name, "max_captures"))) {
            /* .NET listen is raw: these compatibility options have no effect. */
        } else if (!listen && !strcasecmp(name, "address")) {
            if (!nm_ble_payload_normalize_address(value, r->address))
                return false;
        } else if (!listen && !strcasecmp(name, "key")) {
            if (!nm_ble_payload_parse_key(value, r->key, &r->key_length))
                return false;
        } else if (!listen && !strcasecmp(name, "format")) {
            if (!copy_text(r->format, sizeof(r->format), value))
                return false;
        } else if (!listen && !strcasecmp(name, "metric")) {
            if (!copy_text(r->metric, sizeof(r->metric), value))
                return false;
        } else if (!listen && !strcasecmp(name, "nonce_len")) {
            if (!integer(value, 1, 16, &number))
                return false;
            r->nonce_length = (unsigned)number;
        } else if (!listen && !strcasecmp(name, "tag_len")) {
            if (!integer(value, 12, 16, &number))
                return false;
            r->tag_length = (unsigned)number;
        } else if (!listen && !strcasecmp(name, "nonce_at")) {
            if (strcasecmp(value, "start") && strcasecmp(value, "end"))
                return false;
            r->nonce_at_end = !strcasecmp(value, "end");
        } else if (!listen &&
                   (!strcasecmp(name, "metric_scale") || !strcasecmp(name, "metric_offset"))) {
            char *end;
            errno = 0;
            double n = strtod(value, &end);
            if (errno || end == value || *end || !isfinite(n))
                return false;
        } else
            return false;
    }
    lower(r->format);
    lower(r->payload);
    if (strcmp(r->payload, "raw") && strcmp(r->payload, "manufacturer") &&
        strcmp(r->payload, "service"))
        return false;
    if (listen) {
        if (!strcmp(r->payload, "raw") && r->company >= 0)
            strcpy(r->payload, "manufacturer");
        if (!strcmp(r->payload, "raw") && r->uuid_length)
            strcpy(r->payload, "service");
    } else {
        if (!*r->address) {
            *error = "Missing BLE address";
            return false;
        }
        const nm_ble_decoder *decoder = nm_ble_decoder_find(r->format);
        if (!decoder && strcmp(r->format, "raw") && strcmp(r->format, "aesgcm") &&
            strcmp(r->format, "aesctr"))
            return false;
        const char *key_error = nm_ble_decoder_key_error(decoder, r->key_length);
        if (key_error) {
            *error = key_error;
            return false;
        }
        if (decoder) {
            if (!payload_set)
                strcpy(r->payload, decoder->service_uuid ? "service" : "manufacturer");
            if (!company_set)
                r->company = decoder->manufacturer_id;
            if (!service_set && decoder->service_uuid) {
                r->uuid[0] = decoder->service_uuid & 255;
                r->uuid[1] = decoder->service_uuid >> 8;
                r->uuid_length = 2;
            }
        } else if (!r->key_length)
            strcpy(r->format, "raw");
        /* Canonicalize punctuation in metric names, as the .NET selector does. */
        size_t used = 0;
        bool separator = false;
        for (const unsigned char *p = (unsigned char *)r->metric; *p; ++p) {
            if (isalnum(*p)) {
                if (separator && used)
                    r->metric[used++] = '_';
                r->metric[used++] = (char)tolower(*p);
                separator = false;
            } else
                separator = true;
        }
        r->metric[used] = 0;
    }
    *error = NULL;
    return true;
}
static void hex(nm_cmd_output *out, nm_ble_bytes bytes)
{
    for (size_t i = 0; i < bytes.length && out->valid; ++i)
        nm_cmd_output_append(out, "%02X", bytes.bytes[i]);
}
static void capture(nm_cmd_output *out, const char *address, const char *type, nm_ble_bytes bytes)
{
    nm_cmd_output_append(out, "BLE address: %s\nPayload (%s): ", address, type);
    hex(out, bytes);
    nm_cmd_output_append(out, "\n");
}
static nm_cmd_result failure(const char *message)
{
    return (nm_cmd_result){.output = nm_bulk_strdup(message)};
}
nm_cmd_result nm_ble_cmd_run(const nm_ble_command *r, const atomic_bool *cancellation)
{
    if (!r)
        return failure("Invalid BLE command request");
    if (cancellation && atomic_load(cancellation))
        return failure("BLE command canceled or timed out");
    int64_t start = nm_ble_buffer_now_us();
    nm_ble_snapshot *snapshot = r->injected ? NULL : nm_ble_buffer_acquire();
    nm_cmd_result result = {0};
    if (!r->injected &&
        (!nm_ble_buffer_available() || !snapshot || nm_ble_snapshot_incomplete(snapshot))) {
        result = failure("BLE scanner unavailable or captured history incomplete");
        goto done;
    }
    nm_cmd_output out;
    if (!nm_cmd_output_init(&out, 48 * 1024)) {
        result = nm_cmd_output_finish(&out, false);
        goto done;
    }
    const nm_ble_decoder *decoder = r->listen ? NULL : nm_ble_decoder_find(r->format);
    char *decoded = decoder ? nm_bulk_calloc(8192, 1) : NULL;
    if (decoder && !decoded) {
        free(out.text);
        result = failure("BLE decoded output allocation failed");
        goto done;
    }
    size_t count = r->injected ? 1 : nm_ble_snapshot_count(snapshot), captured = 0, samples = 0;
    double mean = 0;
    for (size_t i = 0; i < count; ++i) {
        if ((cancellation && atomic_load(cancellation)) ||
            nm_ble_buffer_now_us() - start >= (int64_t)r->timeout_ms * 1000) {
            free(out.text);
            free(decoded);
            result = failure("BLE command canceled or timed out");
            goto done;
        }
        nm_ble_advertisement item = {0};
        if (r->injected) {
            memcpy(item.data, r->raw, r->raw_length);
            item.data_length = r->raw_length;
            strcpy(item.address, r->listen ? "raw_input" : r->address);
        } else {
            int64_t received;
            if (!nm_ble_snapshot_read(snapshot, i, &item, &received, NULL)) {
                out.valid = false;
                break;
            }
            int64_t age = nm_ble_snapshot_time(snapshot) - received;
            if (!r->listen && (strcmp(r->address, item.address) || age < 0 || age > 70000000))
                continue;
        }
        const char *type = r->injected ? "raw_input" : "raw";
        nm_ble_bytes payload =
            r->injected ? (nm_ble_bytes){item.data, item.data_length}
                        : nm_ble_payload_advertisement_payload(&item, &type, r->company, r->payload,
                                                               r->uuid, r->uuid_length);
        if (!payload.length)
            continue;
        if (r->listen) {
            nm_cmd_output_append(&out, "\n--- Capture %zu ---\n", ++captured);
            capture(&out, item.address, type, payload);
        } else if (decoder) {
            nm_ble_metric_selection selection = {.requested = nm_ble_metric_canonical(r->metric)};
            bool ok = nm_ble_decoder_decode_metric(decoder, payload, type, item.address, r->key,
                                                   r->key_length, decoded, 8192, &selection);
            if (!ok)
                continue;
            /* raw_payload intentionally bypasses the snapshot metric requirement. */
            if (!r->injected &&
                (selection.matches != 1 || !selection.available || !isfinite(selection.value)))
                continue;
            out.used = out.lines = 0;
            out.text[0] = 0;
            nm_cmd_output_append(&out, "%s\n", decoded);
            if (!r->injected) {
                ++samples;
                mean += (selection.value - mean) / (double)samples;
            }
            ++captured;
        } else {
            uint8_t plaintext[NM_BLE_ADVERTISEMENT_MAX];
            nm_ble_bytes clear = {0};
            bool ok = nm_ble_payload_decrypt_payload(r->format, payload, r->key, r->key_length,
                                                     r->nonce_length, r->tag_length,
                                                     r->nonce_at_end, plaintext, &clear);
            out.used = out.lines = 0;
            out.text[0] = 0;
            capture(&out, item.address, type, payload);
            nm_cmd_output_append(&out, "Decrypted: ");
            hex(&out, ok ? clear : payload);
            nm_cmd_output_append(&out, "\n%s",
                                 ok ? "" : "Error: Decryption failed; showing raw payload.\n");
            ++captured;
        }
        if (!out.valid)
            break;
    }
    if (r->listen)
        nm_cmd_output_append(&out, "BLE listen captured %zu advertisement(s).\n", captured);
    else if (samples)
        nm_cmd_output_append(&out, "Window average: %s=%.10g (%zu readings)\n", r->metric, mean,
                             samples);
    else if (!captured)
        nm_cmd_output_append(
            &out, "No usable BLE advertisements in the configured measurement window.\n%s",
            decoded && *decoded ? decoded : "");
    free(decoded);
    result = nm_cmd_output_finish(&out, r->listen || captured != 0);
done:
    nm_ble_snapshot_release(snapshot);
    return result;
}
