#include "camera_capture.h"
#include "camera_http.h"
#include "camera_rtsp.h"
#include "camera_xml.h"
#include "cmd_processor_message.h"
#include <assert.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
bool nm_camera_rtsp(const char *url, const char *username, const char *password,
                    unsigned timeout_ms, const atomic_bool *cancel, nm_camera_image *image)
{
    (void)url;
    (void)username;
    (void)password;
    (void)timeout_ms;
    (void)cancel;
    *image = (nm_camera_image){0};
    return false;
}
static unsigned mode, requests;
static int64_t clock_us;
static atomic_bool cancellation;
/* Minimal framed JPEG tests the transport contract, not image decoding. */
static const uint8_t jpeg[] = {0xff, 0xd8, 0xff, 0xc0, 0, 11, 8, 0, 48, 0,  64, 1, 1,    0x11,
                               0,    0xff, 0xda, 0,    8, 1,  1, 0, 0,  63, 0,  0, 0xff, 0xd9};
int64_t nm_camera_now_us(void)
{
    return clock_us;
}
void nm_camera_random(uint8_t *out, size_t n)
{
    memset(out, 0x45, n);
}
bool nm_camera_hash(bool sha1, const uint8_t *in, size_t n, uint8_t *out, size_t capacity)
{
    assert(capacity >= (sha1 ? 20U : 32U));
    unsigned len;
    return EVP_Digest(in, n, out, &len, sha1 ? EVP_sha1() : EVP_sha256(), NULL) == 1;
}
bool nm_camera_http(const char *url, const char *body, const char *action, const char *username,
                    const char *password, unsigned ms, const atomic_bool *cancel, size_t limit,
                    nm_camera_http_reply *reply)
{
    ++requests;
    assert(ms && limit <= NM_CMD_RAW_MAX);
    assert(!strcmp(username, "test&user") && !strcmp(password, "secret"));
    assert(cancel == &cancellation);
    *reply = (nm_camera_http_reply){0};
    if (mode == 1) {
        clock_us += 10000001;
        return false;
    }
    if (mode == 2) {
        atomic_store(&cancellation, true);
        return false;
    }
    const char *xml;
    if (body) {
        assert(strstr(body, "test&amp;user") && strstr(body, "PasswordDigest") &&
               !strstr(body, "secret"));
        if (strstr(action, "GetProfiles"))
            xml = "<s:Envelope><s:Body><m:GetProfilesResponse><m:Profiles "
                  "token=\"Actual\"/></m:GetProfilesResponse></s:Body></s:Envelope>";
        else if (strstr(action, "GetSnapshotUri")) {
            if (!strstr(body, ">Actual<"))
                return false;
            xml = mode == 3 ? "<Envelope><Uri>http://evil.test/leak</Uri></Envelope>"
                            : "<Envelope><Uri>/image.jpg?token=private&amp;x=2</Uri></Envelope>";
        } else if (strstr(action, "GetCapabilities"))
            xml = "<Envelope><Media><XAddr>http://camera.test:2020/custom/media_service</XAddr></"
                  "Media></Envelope>";
        else
            return false;
        reply->data = (uint8_t *)nm_bulk_strdup(xml);
        reply->length = strlen(xml);
    } else {
        assert(strstr(url, "camera.test") && strstr(url, "image.jpg"));
        reply->length = sizeof(jpeg);
        reply->data = nm_bulk_calloc(sizeof(jpeg) + 1, 1);
        memcpy(reply->data, jpeg, sizeof(jpeg));
        if (mode == 4)
            reply->data[1] = 0;
    }
    reply->status = 200;
    return true;
}
static void release(nm_cmd_result *r)
{
    free(r->output);
    free(r->raw_data);
}
static void xml_tests(void)
{
    char value[128];
    assert(nm_camera_xml_value("<?xml version='1.0'?><s:E><m:Uri>a&amp;b&#x2f;c</m:Uri></s:E>",
                               "Uri", NULL, 0, value, sizeof(value)));
    assert(!strcmp(value, "a&b/c"));
    assert(nm_camera_xml_value("<E><Profiles token='x&amp;y'/><Profiles token='second'/></E>",
                               "Profiles", "token", 1, value, sizeof(value)) &&
           !strcmp(value, "second"));
    assert(!nm_camera_xml_value("<E><Uri>good</Uri></BAD>", "Uri", NULL, 0, value, sizeof(value)));
    assert(!nm_camera_xml_value("<!DOCTYPE E SYSTEM 'file:///secret'><E><Uri>&xxe;</Uri></E>",
                                "Uri", NULL, 0, value, sizeof(value)));
    assert(!nm_camera_xml_value("<E><Uri>&#0;</Uri></E>", "Uri", NULL, 0, value, sizeof(value)));
    assert(
        !nm_camera_xml_value("<E><Uri><nested/></Uri></E>", "Uri", NULL, 0, value, sizeof(value)));
    assert(!nm_camera_xml_value("<E><Uri>oversized</Uri></E>", "Uri", NULL, 0, value, 4));
    assert(nm_camera_xml_escape("<&\"'>", value, sizeof(value)) &&
           !strcmp(value, "&lt;&amp;&quot;&apos;&gt;"));
    /* Every truncation of an otherwise valid XML response must fail safely. */
    const char *valid = "<s:E><m:Uri>http://camera.test/a?b=1&amp;c=2</m:Uri></s:E>";
    char truncated[128];
    for (size_t i = 0; i < strlen(valid); ++i) {
        memcpy(truncated, valid, i);
        truncated[i] = 0;
        assert(!nm_camera_xml_value(truncated, "Uri", NULL, 0, value, sizeof(value)));
    }
}
int main(void)
{
    xml_tests();
    nm_camera_command command;
    const char *error;
    const char *args =
        "--address camera.test --protocol onvif --username 'test&user' --password secret";
    assert(nm_camera_cmd_parse("--address rtsp://user%40name:p%3Ass@camera.test/stream8", &command,
                               &error));
    assert(!strcmp(command.username, "user@name") && !strcmp(command.password, "p:ss"));
    assert(!strcmp(command.address, "rtsp://camera.test/stream8"));
    assert(!nm_camera_cmd_parse("--address rtsp://user:%00@camera.test/stream8", &command, &error));
    assert(nm_camera_cmd_parse(args, &command, &error));
    assert(!command.rtsp && !strcmp(command.profile_token, "Profile_1"));
    const char *bad[] = {"",
                         "--address x --protocol invalid",
                         "--address x --onvif_port 0",
                         "--address x --rtsp_port 65536",
                         "--address x --allow_insecure_tls true",
                         "--address x --ffmpeg_path /tmp/x",
                         "--address x --high_detail whatever",
                         "--address x --unknown true"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); ++i)
        assert(!nm_camera_cmd_parse(bad[i], &command, &error));
    assert(nm_camera_cmd_parse(args, &command, &error));
    nm_cmd_result r = nm_camera_cmd_run(&command, &cancellation);
    assert(r.success && r.raw_length == sizeof(jpeg) && !memcmp(r.raw_data, jpeg, sizeof(jpeg)));
    assert(strstr(r.output, "\"width\":64") && !strstr(r.output, "private"));
    yyjson_mut_doc *doc = nm_json_new();
    yyjson_mut_doc_set_root(doc, yyjson_mut_obj(doc));
    assert(nm_cmd_message_raw(doc, &r));
    yyjson_mut_val *root = yyjson_mut_doc_get_root(doc);
    assert(yyjson_mut_get_uint(yyjson_mut_obj_get(root, "RawDataLength")) == sizeof(jpeg));
    assert(!strcmp(yyjson_mut_get_str(yyjson_mut_obj_get(root, "RawDataMimeType")), "image/jpeg"));
    assert(strlen(yyjson_mut_get_str(yyjson_mut_obj_get(root, "RawData"))) ==
           4 * ((sizeof(jpeg) + 2) / 3));
    release(&r);
    assert(nm_cmd_message_raw(doc, &(nm_cmd_result){0}));
    assert(!*yyjson_mut_get_str(yyjson_mut_obj_get(root, "RawData")));
    yyjson_mut_doc_free(doc);
    for (mode = 1; mode <= 4; ++mode) {
        clock_us = 0;
        requests = 0;
        atomic_store(&cancellation, false);
        command.timeout_ms = 100;
        r = nm_camera_cmd_run(&command, &cancellation);
        assert(!r.success && !r.raw_data && r.output);
        if (mode == 1)
            assert(strstr(r.output, "timed out") && requests == 1);
        if (mode == 2)
            assert(strstr(r.output, "cancelled") && requests == 1);
        release(&r);
    }
    puts("Camera parsing, ONVIF discovery, XML bounds, credentials, cancellation, JPEG and "
         "raw-data replies passed");
}
