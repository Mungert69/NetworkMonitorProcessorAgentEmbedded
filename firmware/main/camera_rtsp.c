#include "camera_rtsp.h"
#include "camera_jpeg.h"
#include "camera_http.h"
#include "cmd_arguments.h"
#include "nm_memory.h"
#include "mbedtls/base64.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#define RTSP_BUFFER 16384
/* All session state/large buffers are owned PSRAM allocations. */
typedef struct {
    int fd;
    int64_t end;
    const atomic_bool *cancel;
    const char *username, *password;
    char url[1024], track[1024], host[256], base[1024];
    char realm[256], nonce[512], opaque[256], session[256];
    char auth[2048], request[4096];
    char response[RTSP_BUFFER];
    uint8_t packet[65536], input[4096];
    size_t input_pos, input_length;
    bool digest, basic, qop;
    unsigned sequence, nc;
} rtsp_session;
static unsigned left(rtsp_session *s)
{
    if (s->cancel && atomic_load(s->cancel))
        return 0;
    int64_t us = s->end - nm_camera_now_us();
    return us > 0 ? (unsigned)((us + 999) / 1000) : 0;
}
static bool io(rtsp_session *s, void *data, size_t n, bool write_data)
{
    uint8_t *p = data;
    while (n && left(s)) {
        if (!write_data && s->input_pos < s->input_length) {
            size_t take = s->input_length - s->input_pos;
            if (take > n)
                take = n;
            memcpy(p, s->input + s->input_pos, take);
            s->input_pos += take;
            p += take;
            n -= take;
            continue;
        }
        fd_set set;
        FD_ZERO(&set);
        FD_SET(s->fd, &set);
        struct timeval wait = {.tv_usec = 50000};
        int rc = select(s->fd + 1, write_data ? NULL : &set, write_data ? &set : NULL, NULL, &wait);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (!rc)
            continue;
        ssize_t count =
            write_data ? send(s->fd, p, n, 0) : recv(s->fd, s->input, sizeof(s->input), 0);
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            continue;
        if (count <= 0)
            return false;
        if (!write_data) {
            s->input_pos = 0;
            s->input_length = (size_t)count;
            continue;
        }
        p += (size_t)count;
        n -= (size_t)count;
    }
    return !n;
}
static bool url_parse(const char *url, char *host, size_t host_size, unsigned *port)
{
    if (strncasecmp(url, "rtsp://", 7) || strlen(url) >= 1024)
        return false;
    const char *start = url + 7, *end = strchr(start, '/');
    if (!end)
        end = start + strlen(start);
    const char *colon = memchr(start, ':', (size_t)(end - start));
    /* IPv4/hostname only for this adapter; reject rather than truncate IPv6. */
    size_t len = (size_t)((colon ? colon : end) - start);
    if (!len || len >= host_size)
        return false;
    for (size_t i = 0; i < len; ++i)
        if (!(isalnum((unsigned char)start[i]) || start[i] == '.' || start[i] == '-'))
            return false;
    memcpy(host, start, len);
    host[len] = 0;
    *port = 554;
    if (colon) {
        char number[6];
        len = (size_t)(end - colon - 1);
        if (!len || len >= sizeof(number))
            return false;
        memcpy(number, colon + 1, len);
        number[len] = 0;
        if (!nm_cmd_argument_number(number, 65535, port))
            return false;
    }
    for (const unsigned char *p = (const unsigned char *)url; *p; ++p)
        if (*p <= 32 || *p == 127 || *p == '"' || *p == '\\' || *p == '#')
            return false;
    return true;
}
static bool header(const char *response, const char *key, unsigned index, char *out,
                   size_t capacity)
{
    size_t key_length = strlen(key);
    const char *line = strstr(response, "\r\n");
    if (!line)
        return false;
    line += 2;
    while (*line && strncmp(line, "\r\n", 2)) {
        const char *end = strstr(line, "\r\n");
        if (!end)
            return false;
        if ((size_t)(end - line) > key_length && line[key_length] == ':' &&
            !strncasecmp(line, key, key_length)) {
            if (index-- == 0) {
                const char *start = line + key_length + 1;
                while (start < end && isspace((unsigned char)*start))
                    ++start;
                while (end > start && isspace((unsigned char)end[-1]))
                    --end;
                size_t n = (size_t)(end - start);
                if (n >= capacity)
                    return false;
                memcpy(out, start, n);
                out[n] = 0;
                return true;
            }
        }
        line = end + 2;
    }
    return false;
}
static bool parameter(const char *value, const char *key, char *out, size_t cap)
{
    while (*value) {
        while (*value && (isspace((unsigned char)*value) || *value == ','))
            ++value;
        const char *name = value;
        while (isalnum((unsigned char)*value) || *value == '-')
            ++value;
        size_t name_len = (size_t)(value - name);
        while (isspace((unsigned char)*value))
            ++value;
        if (*value++ != '=')
            return false;
        while (isspace((unsigned char)*value))
            ++value;
        bool quoted = *value == '"';
        if (quoted)
            ++value;
        const char *start = value;
        while (*value &&
               (quoted ? *value != '"' : *value != ',' && !isspace((unsigned char)*value))) {
            if ((unsigned char)*value < 32 || *value == '\\')
                return false;
            ++value;
        }
        const char *end = value;
        if (quoted && *value++ != '"')
            return false;
        if (strlen(key) == name_len && !strncasecmp(name, key, name_len)) {
            size_t n = (size_t)(end - start);
            if (n >= cap)
                return false;
            memcpy(out, start, n);
            out[n] = 0;
            return true;
        }
        while (*value && *value != ',')
            ++value;
    }
    return false;
}
static bool md5_text(const char *text, char out[33])
{
    uint8_t digest[16];
    if (!nm_camera_md5((const uint8_t *)text, strlen(text), digest))
        return false;
    for (unsigned i = 0; i < 16; ++i)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    return true;
}
static bool quoted(const char *in, char *out, size_t cap)
{
    size_t n = 0;
    for (; *in; ++in) {
        if ((unsigned char)*in < 32 || *in == 127)
            return false;
        if (*in == '"' || *in == '\\') {
            if (n + 1 >= cap)
                return false;
            out[n++] = '\\';
        }
        if (n + 1 >= cap)
            return false;
        out[n++] = *in;
    }
    out[n] = 0;
    return true;
}
static bool auth(rtsp_session *s, const char *method, const char *url)
{
    *s->auth = 0;
    if (s->digest) {
        char text[1792], ha1[33], ha2[33], response[33], user[256], realm[512], nonce[1024],
            opaque[512];
        if (!quoted(s->username, user, sizeof(user)) || !quoted(s->realm, realm, sizeof(realm)) ||
            !quoted(s->nonce, nonce, sizeof(nonce)) || !quoted(s->opaque, opaque, sizeof(opaque)))
            return false;
        int n = snprintf(text, sizeof(text), "%s:%s:%s", s->username, s->realm, s->password);
        if (n < 0 || (size_t)n >= sizeof(text) || !md5_text(text, ha1))
            return false;
        n = snprintf(text, sizeof(text), "%s:%s", method, url);
        if (n < 0 || (size_t)n >= sizeof(text) || !md5_text(text, ha2))
            return false;
        char cnonce[33] = "", qop[128] = "";
        if (s->qop) {
            uint8_t random[16];
            nm_camera_random(random, sizeof(random));
            for (unsigned i = 0; i < 16; ++i)
                snprintf(cnonce + 2 * i, 3, "%02x", random[i]);
            ++s->nc;
            n = snprintf(text, sizeof(text), "%s:%s:%08x:%s:auth:%s", ha1, s->nonce, s->nc, cnonce,
                         ha2);
            snprintf(qop, sizeof(qop), ", qop=auth, nc=%08x, cnonce=\"%s\"", s->nc, cnonce);
        } else
            n = snprintf(text, sizeof(text), "%s:%s:%s", ha1, s->nonce, ha2);
        if (n < 0 || (size_t)n >= sizeof(text) || !md5_text(text, response))
            return false;
        n = snprintf(s->auth, sizeof(s->auth),
                     "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", "
                     "uri=\"%s\", response=\"%s\"%s%s%s%s\r\n",
                     user, realm, nonce, url, response, qop, *opaque ? ", opaque=\"" : "", opaque,
                     *opaque ? "\"" : "");
        return n > 0 && (size_t)n < sizeof(s->auth);
    }
    if (s->basic) {
        char text[512], encoded[685];
        size_t used;
        int n = snprintf(text, sizeof(text), "%s:%s", s->username, s->password);
        if (n < 0 || (size_t)n >= sizeof(text) ||
            mbedtls_base64_encode((uint8_t *)encoded, sizeof(encoded), &used, (const uint8_t *)text,
                                  (size_t)n))
            return false;
        n = snprintf(s->auth, sizeof(s->auth), "Authorization: Basic %s\r\n", encoded);
        return n > 0 && (size_t)n < sizeof(s->auth);
    }
    return true;
}
static bool response(rtsp_session *s, int *status)
{
    size_t n = 0;
    /* Read exactly the RTSP response, preserving following interleaved bytes. */
    while (n + 1 < sizeof(s->response)) {
        if (!io(s, s->response + n, 1, false))
            return false;
        s->response[++n] = 0;
        if (n >= 4 && !memcmp(s->response + n - 4, "\r\n\r\n", 4))
            break;
    }
    if (n + 1 == sizeof(s->response) || sscanf(s->response, "RTSP/1.0 %d", status) != 1)
        return false;
    char length[16];
    unsigned cseq;
    if (!header(s->response, "CSeq", 0, length, sizeof(length)) ||
        !nm_cmd_argument_number(length, UINT_MAX, &cseq) || cseq != s->sequence)
        return false;
    unsigned bytes = 0;
    if (header(s->response, "Content-Length", 0, length, sizeof(length))) {
        if (strcmp(length, "0") && !nm_cmd_argument_number(length, RTSP_BUFFER - 1, &bytes))
            return false;
    }
    if (bytes >= sizeof(s->response) - n)
        return false;
    if (bytes && !io(s, s->response + n, bytes, false))
        return false;
    s->response[n + bytes] = 0;
    return true;
}
static bool request(rtsp_session *s, const char *method, const char *url, const char *extra)
{
    for (unsigned retry = 0; retry < 2 && left(s); ++retry) {
        if (!auth(s, method, url))
            return false;
        int n = snprintf(
            s->request, sizeof(s->request),
            "%s %s RTSP/1.0\r\nCSeq: %u\r\nUser-Agent: NetworkMonitor-ESP32\r\n%s%s%s%s\r\n",
            method, url, ++s->sequence, s->auth, *s->session ? "Session: " : "", s->session,
            *s->session ? "\r\n" : "");
        if (n < 0 || (size_t)n >= sizeof(s->request))
            return false;
        if (extra && *extra) {
            size_t used = (size_t)n - 2, len = strlen(extra);
            if (used + len + 3 > sizeof(s->request))
                return false;
            memcpy(s->request + used, extra, len);
            memcpy(s->request + used + len, "\r\n", 3);
            n = (int)(used + len + 2);
        }
        if (!io(s, s->request, (size_t)n, true))
            return false;
        int status;
        if (!response(s, &status))
            return false;
        if (status >= 200 && status < 300)
            return true;
        if (status != 401 || retry || !*s->username)
            return false;
        char challenge[1536];
        bool basic = false, found = false;
        for (unsigned i = 0;
             i < 8 && header(s->response, "WWW-Authenticate", i, challenge, sizeof(challenge));
             ++i) {
            if (!strncasecmp(challenge, "Basic ", 6))
                basic = true;
            if (strncasecmp(challenge, "Digest ", 7))
                continue;
            if (!parameter(challenge + 7, "realm", s->realm, sizeof(s->realm)) ||
                !parameter(challenge + 7, "nonce", s->nonce, sizeof(s->nonce)))
                return false;
            char algorithm[32], qop[128];
            if (parameter(challenge + 7, "algorithm", algorithm, sizeof(algorithm)) &&
                strcasecmp(algorithm, "MD5"))
                return false;
            s->qop = parameter(challenge + 7, "qop", qop, sizeof(qop));
            if (s->qop && strcmp(qop, "auth") && strcmp(qop, "auth,auth-int") &&
                strcmp(qop, "auth, auth-int"))
                return false;
            *s->opaque = 0;
            (void)parameter(challenge + 7, "opaque", s->opaque, sizeof(s->opaque));
            s->digest = true;
            found = true;
            break;
        }
        if (!found) {
            if (!basic)
                return false;
            s->basic = true;
        }
    }
    return false;
}
static bool track_url(rtsp_session *s, const char *control)
{
    int n;
    if (!strncasecmp(control, "rtsp://", 7))
        n = snprintf(s->track, sizeof(s->track), "%s", control);
    else if (*control == '/') {
        const char *end = strchr(s->base + 7, '/');
        size_t prefix = end ? (size_t)(end - s->base) : strlen(s->base);
        n = snprintf(s->track, sizeof(s->track), "%.*s%s", (int)prefix, s->base, control);
    } else
        n = snprintf(s->track, sizeof(s->track), "%s%s%s", s->base,
                     s->base[strlen(s->base) - 1] == '/' ? "" : "/", control);
    char host[256];
    unsigned port, original_port;
    if (n < 0 || (size_t)n >= sizeof(s->track) ||
        !url_parse(s->url, host, sizeof(host), &original_port) ||
        !url_parse(s->track, host, sizeof(host), &port) || strcasecmp(host, s->host) ||
        port != original_port)
        return false;
    return true;
}
static bool describe(rtsp_session *s)
{
    if (!request(s, "DESCRIBE", s->url, "Accept: application/sdp\r\n"))
        return false;
    strcpy(s->base, s->url);
    char base[1024];
    if (header(s->response, "Content-Base", 0, base, sizeof(base))) {
        char host[256];
        unsigned port, original_port;
        if (!url_parse(base, host, sizeof(host), &port) || strcasecmp(host, s->host) ||
            !url_parse(s->url, host, sizeof(host), &original_port) || port != original_port)
            return false;
        strcpy(s->base, base);
    }
    const char *sdp = strstr(s->response, "\r\n\r\n");
    if (!sdp)
        return false;
    sdp += 4;
    bool video = false, jpeg = false;
    while (*sdp) {
        const char *end = strchr(sdp, '\n');
        size_t n = end ? (size_t)(end - sdp) : strlen(sdp);
        while (n && sdp[n - 1] == '\r')
            --n;
        if (n >= 2 && !memcmp(sdp, "m=", 2)) {
            video = n >= 8 && !memcmp(sdp, "m=video ", 8);
            jpeg = false;
            if (video) {
                char line[256];
                if (n >= sizeof(line))
                    return false;
                memcpy(line, sdp, n);
                line[n] = 0;
                char *tokens = line;
                while (*tokens) {
                    if (tokens > line && tokens[-1] == ' ' && !strcmp(tokens, "26"))
                        jpeg = true;
                    if (tokens > line && tokens[-1] == ' ' && !strncmp(tokens, "26 ", 3))
                        jpeg = true;
                    ++tokens;
                }
            }
        } else if (video && n >= 10 && !memcmp(sdp, "a=control:", 10) && jpeg) {
            char control[1024];
            if (n - 10 >= sizeof(control))
                return false;
            memcpy(control, sdp + 10, n - 10);
            control[n - 10] = 0;
            return track_url(s, control);
        }
        if (!end)
            break;
        sdp = end + 1;
    }
    return false;
}
bool nm_camera_rtsp(const char *url, const char *username, const char *password,
                    unsigned timeout_ms, const atomic_bool *cancel, nm_camera_image *image)
{
    *image = (nm_camera_image){0};
    rtsp_session *s = nm_bulk_calloc(1, sizeof(*s));
    if (!s)
        return false;
    s->fd = -1;
    s->end = nm_camera_now_us() + (int64_t)timeout_ms * 1000;
    s->cancel = cancel;
    s->username = username;
    s->password = password;
    unsigned port;
    bool ok = false;
    nm_camera_jpeg *jpeg = NULL;
    if (!url_parse(url, s->host, sizeof(s->host), &port))
        goto done;
    strcpy(s->url, url);
    s->fd = nm_camera_socket_connect(s->host, port, left(s), cancel);
    if (s->fd < 0 || s->fd >= FD_SETSIZE)
        goto done;
    if (!describe(s) ||
        !request(s, "SETUP", s->track, "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"))
        goto done;
    if (!header(s->response, "Session", 0, s->session, sizeof(s->session)))
        goto done;
    char *semicolon = strchr(s->session, ';');
    if (semicolon)
        *semicolon = 0;
    if (!*s->session || !request(s, "PLAY", s->url, NULL))
        goto done;
    jpeg = nm_camera_jpeg_new();
    if (!jpeg)
        goto done;
    while (left(s)) {
        uint8_t prefix[4];
        if (!io(s, prefix, 4, false) || prefix[0] != '$')
            break;
        size_t bytes = ((size_t)prefix[2] << 8) | prefix[3];
        if (!bytes || !io(s, s->packet, bytes, false))
            break;
        if (prefix[1] == 0 && nm_camera_jpeg_packet(jpeg, s->packet, bytes)) {
            image->data = nm_camera_jpeg_take(jpeg, &image->length, &image->width, &image->height);
            ok = image->data && left(s);
            break;
        }
    }
done:
    /* Closing TCP terminates the short-lived RTSP session, including on cancellation. */
    if (s->fd >= 0)
        close(s->fd);
    if (!ok) {
        free(image->data);
        *image = (nm_camera_image){0};
    }
    nm_camera_jpeg_free(jpeg);
    free(s);
    return ok;
}
