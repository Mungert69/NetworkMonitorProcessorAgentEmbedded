#include "camera_capture_cmd_processor.h"
#include "camera_capture.h"
#include "nm_memory.h"
#include <string.h>
#include <strings.h>

const char *nm_camera_cmd_help(void)
{
    return "CameraCapture captures one network-camera JPEG and returns RawData.\n"
           "Required: --address <host|http(s) URL|rtsp URL>\n"
           "Options: --protocol onvif|rtsp (default rtsp), --username <value>, "
           "--password <value>, --profile_token <value> (default Profile_1), "
           "--onvif_port <port>, --rtsp_port <port>, --rtsp_path <path>, "
           "--high_detail true|false.\n"
           "ESP32 supports RTSP RTP/JPEG (for Tapo C211 use /stream8) and ONVIF JPEG snapshots. "
           "H.264/H.265 decoding and FFmpeg are unavailable; ONVIF JPEG profiles are discovered as "
           "a fallback. Native JPEG size is preserved; "
           "high_detail selects the requested width target in the summary, not image resizing. "
           "Maximum JPEG is 65536 bytes. HTTPS certificates must be trusted; "
           "--allow_insecure_tls true is rejected. A direct JPEG URL accepts --protocol onvif.\n";
}
static bool copy(char *out, size_t capacity, const char *in)
{
    size_t length = strlen(in);
    if (length >= capacity)
        return false;
    for (size_t i = 0; i < length; ++i)
        if ((unsigned char)in[i] < 32 || (unsigned char)in[i] == 127)
            return false;
    memcpy(out, in, length + 1);
    return true;
}
static bool boolean(const char *value, bool *out)
{
    if (!strcasecmp(value, "true") || !strcmp(value, "1") || !strcasecmp(value, "yes"))
        *out = true;
    else if (!strcasecmp(value, "false") || !strcmp(value, "0") || !strcasecmp(value, "no"))
        *out = false;
    else
        return false;
    return true;
}
static int hex_digit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}
static bool url_credential(const char *start, size_t length, char *out, size_t cap)
{
    size_t used = 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)start[i];
        if (c == '%') {
            if (length - i < 3 || hex_digit(start[i + 1]) < 0 || hex_digit(start[i + 2]) < 0)
                return false;
            c = (unsigned char)(hex_digit(start[i + 1]) * 16 + hex_digit(start[i + 2]));
            i += 2;
        }
        if (c < 32 || c == 127 || used + 1 >= cap)
            return false;
        out[used++] = (char)c;
    }
    out[used] = 0;
    return true;
}
static bool extract_credentials(nm_camera_command *request)
{
    char *scheme = strstr(request->address, "://");
    if (!scheme)
        return true;
    char *start = scheme + 3, *end = strchr(start, '/');
    if (!end)
        end = start + strlen(start);
    char *at = memchr(start, '@', (size_t)(end - start));
    if (!at)
        return true;
    char *colon = memchr(start, ':', (size_t)(at - start));
    char username[128], password[256] = "";
    if (!url_credential(start, (size_t)((colon ? colon : at) - start), username,
                        sizeof(username)) ||
        (colon && !url_credential(colon + 1, (size_t)(at - colon - 1), password, sizeof(password))))
        return false;
    if (!*request->username)
        strcpy(request->username, username);
    if (!*request->password)
        strcpy(request->password, password);
    memmove(start, at + 1, strlen(at + 1) + 1);
    return true;
}
bool nm_camera_cmd_parse(const char *arguments, nm_camera_command *request, const char **error)
{
    if (!request || !error)
        return false;
    *error = "Invalid CameraCapture arguments. Use --address <host|url>; see command help.";
    *request = (nm_camera_command){.timeout_ms = 600000, .rtsp = true};
    strcpy(request->profile_token, "Profile_1");
    if (!arguments || strlen(arguments) > 4096)
        return false;
    char option[1152], value[1024];
    const char *cursor = arguments;
    while (*cursor) {
        if (!nm_cmd_argument_token(&cursor, option, sizeof(option)))
            return false;
        if (!*option)
            break;
        if (strncmp(option, "--", 2))
            return false;
        char *key = option + 2, *argument = strchr(key, '=');
        if (argument)
            *argument++ = 0;
        else {
            if (!nm_cmd_argument_token(&cursor, value, sizeof(value)))
                return false;
            argument = value;
        }
        if (!strcasecmp(key, "address")) {
            if (!copy(request->address, sizeof(request->address), argument))
                return false;
        } else if (!strcasecmp(key, "username")) {
            if (!copy(request->username, sizeof(request->username), argument))
                return false;
        } else if (!strcasecmp(key, "password")) {
            if (!copy(request->password, sizeof(request->password), argument))
                return false;
        } else if (!strcasecmp(key, "profile_token")) {
            if (!*argument ||
                !copy(request->profile_token, sizeof(request->profile_token), argument))
                return false;
        } else if (!strcasecmp(key, "rtsp_path")) {
            if (!copy(request->rtsp_path, sizeof(request->rtsp_path), argument))
                return false;
        } else if (!strcasecmp(key, "onvif_port")) {
            if (!nm_cmd_argument_number(argument, 65535, &request->onvif_port))
                return false;
        } else if (!strcasecmp(key, "rtsp_port")) {
            if (!nm_cmd_argument_number(argument, 65535, &request->rtsp_port))
                return false;
        } else if (!strcasecmp(key, "protocol")) {
            if (strcasecmp(argument, "rtsp") && strcasecmp(argument, "onvif"))
                return false;
            request->rtsp = !strcasecmp(argument, "rtsp");
        } else if (!strcasecmp(key, "high_detail")) {
            if (!boolean(argument, &request->high_detail))
                return false;
        } else if (!strcasecmp(key, "allow_insecure_tls")) {
            bool insecure;
            if (!boolean(argument, &insecure))
                return false;
            if (insecure) {
                *error = "ESP32 CameraCapture requires verified HTTPS; allow_insecure_tls=true is "
                         "unsupported.";
                return false;
            }
        } else if (!strcasecmp(key, "ffmpeg_path")) {
            if (strcmp(argument, "ffmpeg")) {
                *error = "ESP32 CameraCapture cannot execute FFmpeg.";
                return false;
            }
        } else
            return false;
    }
    if (!*request->address || !extract_credentials(request))
        return false;
    *error = NULL;
    return true;
}
nm_cmd_result nm_camera_cmd_run(const nm_camera_command *request, const atomic_bool *cancel)
{
    if (!request)
        return (nm_cmd_result){.output = nm_bulk_strdup("Invalid CameraCapture request")};
    return nm_camera_capture(request, cancel);
}
