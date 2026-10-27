#include "camera_capture.h"
#include "camera_http.h"
#include "camera_rtsp.h"
#include "camera_xml.h"
#include "nm_json.h"
#include "mbedtls/base64.h"
#include <ctype.h>
#include <stdio.h>
#include <strings.h>
#include <time.h>

#define URL_SIZE 1024
#define SOAP_LIMIT 32768
#define SERVICE_LIMIT 12
#define PROFILE_LIMIT 8
/* Workspace lives in PSRAM, not on the 16 KiB command stack. */
typedef struct {
    char scheme[6], host[256], origin[320];
    unsigned port;
} camera_origin;
typedef struct {
    const nm_camera_command *command;
    const atomic_bool *cancel;
    int64_t end;
    camera_origin origin;
    char services[SERVICE_LIMIT][URL_SIZE];
    unsigned service_count;
    char profiles[PROFILE_LIMIT][128];
    unsigned profile_count;
    char body[4096], operation[1024], snapshot[URL_SIZE];
    char escaped[768], xml_user[768];
    unsigned width, height;
    int last_status;
    bool snapshot_attempted;
} capture_context;
static unsigned remaining(capture_context *ctx)
{
    if (ctx->cancel && atomic_load(ctx->cancel))
        return 0;
    int64_t us = ctx->end - nm_camera_now_us();
    return us <= 0 ? 0 : (unsigned)((us + 999) / 1000);
}
static bool origin_parse(const char *address, unsigned override_port, camera_origin *out)
{
    *out = (camera_origin){0};
    const char *host = address;
    bool rtsp = false;
    strcpy(out->scheme, "http");
    if (!strncasecmp(host, "https://", 8)) {
        strcpy(out->scheme, "https");
        host += 8;
    } else if (!strncasecmp(host, "http://", 7))
        host += 7;
    else if (!strncasecmp(host, "rtsp://", 7)) {
        host += 7;
        rtsp = true;
    } else if (strstr(host, "://"))
        return false;
    const char *end = host;
    while (*end && *end != '/' && *end != '?' && *end != '#')
        ++end;
    const char *port = NULL, *host_end = end;
    if (*host == '[') {
        const char *bracket = memchr(host, ']', (size_t)(end - host));
        if (!bracket)
            return false;
        host_end = bracket + 1;
        if (host_end != end) {
            if (*host_end != ':')
                return false;
            port = host_end + 1;
        }
    } else {
        const char *colon = memchr(host, ':', (size_t)(end - host));
        if (colon) {
            host_end = colon;
            port = colon + 1;
        }
    }
    size_t length = (size_t)(host_end - host);
    if (!length || length >= sizeof(out->host))
        return false;
    for (size_t i = 0; i < length; ++i)
        if (!(isalnum((unsigned char)host[i]) || strchr(".-_:[]", host[i])))
            return false;
    memcpy(out->host, host, length);
    out->host[length] = 0;
    out->port = !strcmp(out->scheme, "https") ? 443 : 80;
    if (port) {
        char number[6];
        size_t n = (size_t)(end - port);
        if (!n || n >= sizeof(number))
            return false;
        memcpy(number, port, n);
        number[n] = 0;
        unsigned parsed;
        if (!nm_cmd_argument_number(number, 65535, &parsed))
            return false;
        if (!rtsp)
            out->port = parsed;
    }
    if (override_port)
        out->port = override_port;
    int n =
        snprintf(out->origin, sizeof(out->origin), "%s://%s:%u", out->scheme, out->host, out->port);
    return n > 0 && (size_t)n < sizeof(out->origin);
}
static bool safe_url(capture_context *ctx, const char *value, const char *base, char *out)
{
    char url[URL_SIZE];
    int n;
    if (strstr(value, "://"))
        n = snprintf(url, sizeof(url), "%s", value);
    else if (*value == '/' && value[1] != '/') {
        camera_origin origin;
        if (!origin_parse(base, 0, &origin))
            return false;
        n = snprintf(url, sizeof(url), "%s%s", origin.origin, value);
    } else if (*value && *value != '/' && !strchr(value, ':')) {
        const char *path = strstr(base, "://");
        path = path ? strchr(path + 3, '/') : NULL;
        const char *last = path ? strrchr(path, '/') : NULL;
        size_t prefix = last ? (size_t)(last + 1 - base) : strlen(base);
        n = snprintf(url, sizeof(url), "%.*s%s%s", (int)prefix, base, last ? "" : "/", value);
    } else
        return false;
    if (n <= 0 || (size_t)n >= sizeof(url) || strchr(url, '#') ||
        (strncasecmp(url, "http://", 7) && strncasecmp(url, "https://", 8)))
        return false;
    for (const unsigned char *p = (const unsigned char *)url; *p; ++p)
        if (*p <= 32 || *p == 127 || *p == '\\')
            return false;
    camera_origin origin;
    if (!origin_parse(url, 0, &origin) || strcasecmp(origin.host, ctx->origin.host) ||
        (!strcmp(ctx->origin.scheme, "https") && strcmp(origin.scheme, "https")))
        return false;
    strcpy(out, url);
    return true;
}
static void add_service(capture_context *ctx, const char *value, const char *base)
{
    char url[URL_SIZE];
    if (!safe_url(ctx, value, base, url))
        return;
    for (unsigned i = 0; i < ctx->service_count; ++i)
        if (!strcmp(ctx->services[i], url))
            return;
    if (ctx->service_count < SERVICE_LIMIT)
        strcpy(ctx->services[ctx->service_count++], url);
}
static void add_profile(capture_context *ctx, const char *token)
{
    if (!*token || strlen(token) >= sizeof(ctx->profiles[0]))
        return;
    for (unsigned i = 0; i < ctx->profile_count; ++i)
        if (!strcmp(ctx->profiles[i], token))
            return;
    if (ctx->profile_count < PROFILE_LIMIT)
        strcpy(ctx->profiles[ctx->profile_count++], token);
}
static bool soap_body(capture_context *ctx, const char *operation)
{
    char security[1792] = "";
    if (*ctx->command->username) {
        uint8_t nonce[16], digest[20], combined[320];
        char nonce64[25], digest64[29], created[32];
        size_t written;
        time_t now = time(NULL);
        struct tm utc;
        if (!gmtime_r(&now, &utc) ||
            !strftime(created, sizeof(created), "%Y-%m-%dT%H:%M:%SZ", &utc) ||
            !nm_camera_xml_escape(ctx->command->username, ctx->xml_user, sizeof(ctx->xml_user)))
            return false;
        nm_camera_random(nonce, sizeof(nonce));
        memcpy(combined, nonce, sizeof(nonce));
        size_t len = sizeof(nonce), n = strlen(created);
        memcpy(combined + len, created, n);
        len += n;
        n = strlen(ctx->command->password);
        memcpy(combined + len, ctx->command->password, n);
        len += n;
        if (!nm_camera_hash(true, combined, len, digest, sizeof(digest)) ||
            mbedtls_base64_encode((uint8_t *)nonce64, sizeof(nonce64), &written, nonce,
                                  sizeof(nonce)) ||
            mbedtls_base64_encode((uint8_t *)digest64, sizeof(digest64), &written, digest,
                                  sizeof(digest)))
            return false;
        int count = snprintf(
            security, sizeof(security),
            "<s:Header><wsse:Security s:mustUnderstand=\"1\"><wsse:UsernameToken>"
            "<wsse:Username>%s</wsse:Username><wsse:Password "
            "Type=\"http://docs.oasis-open.org/wss/2004/01/"
            "oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</wsse:Password>"
            "<wsse:Nonce "
            "EncodingType=\"http://docs.oasis-open.org/wss/2004/01/"
            "oasis-200401-wss-soap-message-security-1.0#Base64Binary\">%s</wsse:Nonce>"
            "<wsu:Created>%s</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header>",
            ctx->xml_user, digest64, nonce64, created);
        if (count < 0 || (size_t)count >= sizeof(security))
            return false;
    }
    int n =
        snprintf(ctx->body, sizeof(ctx->body),
                 "<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope "
                 "xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
                 "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/"
                 "oasis-200401-wss-wssecurity-secext-1.0.xsd\" "
                 "xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/"
                 "oasis-200401-wss-wssecurity-utility-1.0.xsd\">%s<s:Body>%s</s:Body></s:Envelope>",
                 security, operation);
    return n > 0 && (size_t)n < sizeof(ctx->body);
}
static bool soap(capture_context *ctx, const char *url, const char *action, const char *operation,
                 nm_camera_http_reply *reply)
{
    *reply = (nm_camera_http_reply){0};
    unsigned ms = remaining(ctx);
    if (ms > 10000)
        ms = 10000; /* One unreachable discovery endpoint cannot use the entire command. */
    return ms && soap_body(ctx, operation) &&
           nm_camera_http(url, ctx->body, action, ctx->command->username, ctx->command->password,
                          ms, ctx->cancel, SOAP_LIMIT, reply);
}
static bool jpeg_dimensions(const uint8_t *data, size_t n, unsigned *width, unsigned *height)
{
    if (n < 12 || data[0] != 0xff || data[1] != 0xd8 || data[n - 2] != 0xff || data[n - 1] != 0xd9)
        return false;
    bool frame = false;
    for (size_t p = 2; p < n - 2;) {
        if (data[p++] != 0xff)
            return false;
        while (p < n && data[p] == 0xff)
            ++p;
        if (p >= n)
            return false;
        uint8_t marker = data[p++];
        if (marker == 0xda)
            return frame; /* Scan data follows; JPEG is passed through unchanged. */
        if (marker == 0xd8 || marker == 0xd9 || marker == 0 || (marker >= 0xd0 && marker <= 0xd7))
            return false;
        if (p + 2 > n)
            return false;
        size_t bytes = ((size_t)data[p] << 8) | data[p + 1];
        if (bytes < 2 || bytes > n - p)
            return false;
        if (marker == 0xc0 || marker == 0xc1 || marker == 0xc2) {
            if (bytes < 8 || data[p + 2] != 8)
                return false;
            *height = ((unsigned)data[p + 3] << 8) | data[p + 4];
            *width = ((unsigned)data[p + 5] << 8) | data[p + 6];
            if (!*width || !*height || *width > 8192 || *height > 8192)
                return false;
            frame = true;
        }
        p += bytes;
    }
    return false;
}
static bool snapshot(capture_context *ctx, const char *url, nm_cmd_result *result)
{
    nm_camera_http_reply reply = {0};
    ctx->snapshot_attempted = true;
    unsigned ms = remaining(ctx);
    if (ms > 20000)
        ms = 20000;
    bool ok = ms &&
              nm_camera_http(url, NULL, NULL, ctx->command->username, ctx->command->password, ms,
                             ctx->cancel, NM_CMD_RAW_MAX, &reply) &&
              remaining(ctx) &&
              jpeg_dimensions(reply.data, reply.length, &ctx->width, &ctx->height);
    if (ok) {
        uint8_t digest[32];
        ok = nm_camera_hash(false, reply.data, reply.length, digest, sizeof(digest));
        if (ok) {
            for (unsigned i = 0; i < 32; ++i)
                snprintf(result->raw_sha256 + 2 * i, 3, "%02x", digest[i]);
            result->raw_data = reply.data;
            result->raw_length = reply.length;
            return true;
        }
    }
    ctx->last_status = reply.status;
    free(reply.data);
    return false;
}
static bool rtsp_snapshot(capture_context *ctx, const char *url, nm_cmd_result *result)
{
    camera_origin origin;
    if (strncasecmp(url, "rtsp://", 7) || !origin_parse(url, 0, &origin) ||
        strcasecmp(origin.host, ctx->origin.host))
        return false;
    nm_camera_image image = {0};
    unsigned ms = remaining(ctx);
    if (ms > 15000)
        ms = 15000;
    if (!ms || !nm_camera_rtsp(url, ctx->command->username, ctx->command->password, ms, ctx->cancel,
                               &image))
        return false;
    uint8_t digest[32];
    unsigned width, height;
    if (!jpeg_dimensions(image.data, image.length, &width, &height) || width != image.width ||
        height != image.height ||
        !nm_camera_hash(false, image.data, image.length, digest, sizeof(digest))) {
        free(image.data);
        return false;
    }
    result->raw_data = image.data;
    result->raw_length = image.length;
    for (unsigned i = 0; i < 32; ++i)
        snprintf(result->raw_sha256 + 2 * i, 3, "%02x", digest[i]);
    ctx->width = image.width;
    ctx->height = image.height;
    snprintf(ctx->snapshot, sizeof(ctx->snapshot), "%s", url);
    return true;
}
static bool try_media(capture_context *ctx, const char *service, nm_cmd_result *result)
{
    bool media2 = strstr(service, "media2") != NULL;
    const char *ns =
        media2 ? "http://www.onvif.org/ver20/media/wsdl" : "http://www.onvif.org/ver10/media/wsdl";
    char action[128];
    nm_camera_http_reply reply = {0};
    ctx->profile_count = 0;
    add_profile(ctx, ctx->command->profile_token);
    snprintf(action, sizeof(action), "%s/GetProfiles", ns);
    snprintf(ctx->operation, sizeof(ctx->operation), "<m:GetProfiles xmlns:m=\"%s\"/>", ns);
    if (soap(ctx, service, action, ctx->operation, &reply)) {
        char token[128];
        for (unsigned i = 0; i < PROFILE_LIMIT; ++i)
            if (nm_camera_xml_value((char *)reply.data, "Profiles", "token", i, token,
                                    sizeof(token)))
                add_profile(ctx, token);
    }
    free(reply.data);
    for (unsigned i = 0; i < ctx->profile_count && remaining(ctx); ++i) {
        if (!nm_camera_xml_escape(ctx->profiles[i], ctx->escaped, sizeof(ctx->escaped)))
            continue;
        int n = snprintf(ctx->operation, sizeof(ctx->operation),
                         "<m:GetSnapshotUri "
                         "xmlns:m=\"%s\"><m:ProfileToken>%s</m:ProfileToken></m:GetSnapshotUri>",
                         ns, ctx->escaped);
        if (n < 0 || (size_t)n >= sizeof(ctx->operation))
            continue;
        snprintf(action, sizeof(action), "%s/GetSnapshotUri", ns);
        bool ok = soap(ctx, service, action, ctx->operation, &reply);
        char uri[URL_SIZE];
        ok = ok && nm_camera_xml_value((char *)reply.data, "Uri", NULL, 0, uri, sizeof(uri)) &&
             safe_url(ctx, uri, service, ctx->snapshot);
        free(reply.data);
        if (ok && snapshot(ctx, ctx->snapshot, result))
            return true;
        /* Media1 exposes JPEG profiles through GetStreamUri even when snapshots
         * are unsupported (including the C211's native JPEG profile). */
        if (!media2) {
            n = snprintf(
                ctx->operation, sizeof(ctx->operation),
                "<m:GetStreamUri xmlns:m=\"%s\" xmlns:t=\"http://www.onvif.org/ver10/schema\">"
                "<m:StreamSetup><t:Stream>RTP-Unicast</t:Stream><t:Transport>"
                "<t:Protocol>RTSP</t:Protocol></t:Transport></m:StreamSetup>"
                "<m:ProfileToken>%s</m:ProfileToken></m:GetStreamUri>",
                ns, ctx->escaped);
            if (n < 0 || (size_t)n >= sizeof(ctx->operation))
                continue;
            snprintf(action, sizeof(action), "%s/GetStreamUri", ns);
            ok = soap(ctx, service, action, ctx->operation, &reply);
            ok = ok && nm_camera_xml_value((char *)reply.data, "Uri", NULL, 0, uri, sizeof(uri));
            free(reply.data);
            if (ok && rtsp_snapshot(ctx, uri, result))
                return true;
        }
    }
    return false;
}
static bool capture(capture_context *ctx, nm_cmd_result *result)
{
    if (ctx->command->rtsp) {
        char url[URL_SIZE], authority[320];
        const char *address = ctx->command->address;
        const char *path = NULL;
        bool explicit_url = !strncasecmp(address, "rtsp://", 7);
        if (explicit_url)
            path = strchr(address + 7, '/');
        int n;
        if (ctx->command->rtsp_port || !explicit_url)
            n = snprintf(authority, sizeof(authority), "%s:%u", ctx->origin.host,
                         ctx->command->rtsp_port ? ctx->command->rtsp_port : 554);
        else
            n = snprintf(authority, sizeof(authority), "%.*s",
                         (int)(path ? (size_t)(path - address - 7) : strlen(address + 7)),
                         address + 7);
        const char *selected = *ctx->command->rtsp_path ? ctx->command->rtsp_path
                               : path                   ? path
                                                        : "/";
        if (n > 0 && (size_t)n < sizeof(authority)) {
            n = snprintf(url, sizeof(url), "rtsp://%s%s%s", authority, *selected == '/' ? "" : "/",
                         selected);
            if (n > 0 && (size_t)n < sizeof(url) && rtsp_snapshot(ctx, url, result))
                return true;
        }
    }
    /* An explicit HTTP(S) path can be a JPEG URL. ONVIF service URLs skip GET. */
    const char *scheme = strstr(ctx->command->address, "://");
    const char *path = scheme ? strchr(scheme + 3, '/') : NULL;
    if (path && path[1] && strncasecmp(ctx->command->address, "rtsp:", 5) &&
        !strstr(path, "onvif")) {
        if (safe_url(ctx, ctx->command->address, ctx->origin.origin, ctx->snapshot) &&
            snapshot(ctx, ctx->snapshot, result))
            return true;
    }
    if (path && (strstr(path, "media_service") || strstr(path, "media2_service")))
        add_service(ctx, ctx->command->address, ctx->origin.origin);
    const char *defaults[] = {"/onvif/media_service", "/onvif/media2_service", "/onvif/Media",
                              "/onvif/media"};
    for (unsigned i = 0; i < 4; ++i)
        add_service(ctx, defaults[i], ctx->origin.origin);
    for (unsigned i = 0; i < ctx->service_count && remaining(ctx); ++i)
        if (try_media(ctx, ctx->services[i], result))
            return true;
    /* Discover advertised media services on standard and Tapo device ports. */
    unsigned ports[] = {ctx->origin.port, 2020, 8080, 8899};
    for (unsigned i = 0; i < 4 && remaining(ctx); ++i) {
        bool duplicate = false;
        for (unsigned k = 0; k < i; ++k)
            if (ports[k] == ports[i])
                duplicate = true;
        if (duplicate)
            continue;
        char device[URL_SIZE];
        snprintf(device, sizeof(device), "%s://%s:%u/onvif/device_service", ctx->origin.scheme,
                 ctx->origin.host, ports[i]);
        nm_camera_http_reply reply;
        unsigned old_count = ctx->service_count;
        if (soap(ctx, device, "http://www.onvif.org/ver10/device/wsdl/GetCapabilities",
                 "<d:GetCapabilities "
                 "xmlns:d=\"http://www.onvif.org/ver10/device/wsdl\"><d:Category>Media</"
                 "d:Category></d:GetCapabilities>",
                 &reply)) {
            char uri[URL_SIZE];
            for (unsigned k = 0; k < SERVICE_LIMIT; ++k)
                if (nm_camera_xml_value((char *)reply.data, "XAddr", NULL, k, uri, sizeof(uri)))
                    add_service(ctx, uri, device);
        }
        free(reply.data);
        for (unsigned k = old_count; k < ctx->service_count && remaining(ctx); ++k)
            if (try_media(ctx, ctx->services[k], result))
                return true;
    }
    return false;
}
nm_cmd_result nm_camera_capture(const nm_camera_command *command, const atomic_bool *cancel)
{
    nm_cmd_result result = {0};
    capture_context *ctx = nm_bulk_calloc(1, sizeof(*ctx));
    if (!ctx) {
        result.output = nm_bulk_strdup("Camera capture failed: local allocation unavailable");
        return result;
    }
    ctx->command = command;
    ctx->cancel = cancel;
    ctx->end = nm_camera_now_us() + (int64_t)command->timeout_ms * 1000;
    const char *error =
        "Camera capture failed: no usable ONVIF JPEG snapshot (maximum 65536 "
        "bytes). Use an RTP/JPEG stream; H264/H265 decoding is unavailable on ESP32.";
    if (!origin_parse(command->address, command->onvif_port, &ctx->origin))
        error = "Camera capture failed: invalid URL or embedded credentials; use username/password "
                "options.";
    else if (capture(ctx, &result) && remaining(ctx)) {
        yyjson_mut_doc *doc = nm_json_new();
        yyjson_mut_val *root = doc ? yyjson_mut_obj(doc) : NULL;
        if (doc)
            yyjson_mut_doc_set_root(doc, root);
        /* Do not echo a camera's query string/token or credentials into LLM output. */
        char *query = strchr(ctx->snapshot, '?');
        if (query)
            *query = 0;
        bool ok = root && nm_json_put_str(doc, root, "status", "success") &&
                  nm_json_put_str(doc, root, "source", ctx->snapshot) &&
                  nm_json_put_str(doc, root, "protocol", command->rtsp ? "rtsp" : "onvif") &&
                  nm_json_put_str(doc, root, "warning",
                                  "ESP32 captured native JPEG; image dimensions are unchanged.") &&
                  nm_json_put(doc, root, "width_target",
                              yyjson_mut_uint(doc, command->high_detail ? 1280 : 1024)) &&
                  nm_json_put(doc, root, "width", yyjson_mut_uint(doc, ctx->width)) &&
                  nm_json_put(doc, root, "height", yyjson_mut_uint(doc, ctx->height)) &&
                  nm_json_put(doc, root, "bytes", yyjson_mut_uint(doc, result.raw_length)) &&
                  nm_json_put_str(doc, root, "mime_type", "image/jpeg") &&
                  nm_json_put_str(doc, root, "raw_data_encoding", "base64") &&
                  nm_json_put_str(doc, root, "raw_data_sha256", result.raw_sha256);
        if (ok)
            result.output = nm_json_write(root, 0, NULL);
        yyjson_mut_doc_free(doc);
        if (result.output)
            result.success = true;
        else
            error = "Camera capture failed: could not construct image summary";
    }
    if (!result.success) {
        free(result.raw_data);
        result.raw_data = NULL;
        result.raw_length = 0;
        if (cancel && atomic_load(cancel))
            error = "Camera capture cancelled.";
        else if (!remaining(ctx))
            error = "Camera capture timed out.";
        if (ctx->snapshot_attempted && remaining(ctx)) {
            char message[256];
            snprintf(message, sizeof(message),
                     "Camera capture failed: snapshot HTTP status %d; requires a complete JPEG no "
                     "larger than %u bytes. Use an RTP/JPEG stream or ONVIF JPEG snapshot.",
                     ctx->last_status, NM_CMD_RAW_MAX);
            result.output = nm_bulk_strdup(message);
        } else
            result.output = nm_bulk_strdup(error);
    }
    free(ctx);
    return result;
}
