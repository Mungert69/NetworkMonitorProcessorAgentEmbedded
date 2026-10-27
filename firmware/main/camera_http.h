#ifndef NM_CAMERA_HTTP_H
#define NM_CAMERA_HTTP_H
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* URL must be absolute HTTP(S), validated by capture policy. Caller owns reply
 * (even on failure). No automatic redirect/credential forwarding. */
typedef struct {
    uint8_t *data;
    size_t length;
    int status;
} nm_camera_http_reply;
bool nm_camera_http(const char *url, const char *body, const char *action, const char *username,
                    const char *password, unsigned timeout_ms, const atomic_bool *cancel,
                    size_t limit, nm_camera_http_reply *reply);
/* Cryptographic/platform primitives, with real host adapters in native tests. */
bool nm_camera_hash(bool sha1, const uint8_t *, size_t, uint8_t *, size_t);
bool nm_camera_md5(const uint8_t *, size_t, uint8_t out[16]);
void nm_camera_random(uint8_t *, size_t);
int64_t nm_camera_now_us(void);
#endif
