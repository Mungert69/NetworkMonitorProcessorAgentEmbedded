#ifndef NM_CAMERA_RTSP_H
#define NM_CAMERA_RTSP_H
#include "cmd_result.h"
/* Authenticated RTSP/1.0, interleaved TCP RTP/JPEG. Owns temporary sockets and
 * returns one owned JPEG. No camera configuration changes or arbitrary redirects. */
typedef struct {
    uint8_t *data;
    size_t length;
    unsigned width, height;
} nm_camera_image;
bool nm_camera_rtsp(const char *url, const char *username, const char *password,
                    unsigned timeout_ms, const atomic_bool *cancel, nm_camera_image *);
/* Platform adapter: nonblocking TCP connect with shared bounded DNS admission. */
int nm_camera_socket_connect(const char *host, unsigned port, unsigned timeout_ms,
                             const atomic_bool *cancel);
#endif
