#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>

static int fuzz_fd = -1;
static int64_t fuzz_clock;
static const uint8_t *fuzz_input;
static size_t fuzz_input_size;

static int fuzz_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
static ssize_t fuzz_send(int, const void *, size_t, int);
static ssize_t fuzz_recv(int, void *, size_t, int);
static int fuzz_close(int);

#define select fuzz_select
#define send fuzz_send
#define recv fuzz_recv
#define close fuzz_close

#include "camera_rtsp.c"

#undef select
#undef send
#undef recv
#undef close

struct nm_camera_jpeg {
    unsigned unused;
};

static int fuzz_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                       struct timeval *timeout)
{
    (void)nfds;
    (void)readfds;
    (void)writefds;
    (void)exceptfds;
    (void)timeout;
    return 1;
}

static ssize_t fuzz_send(int fd, const void *data, size_t size, int flags)
{
    (void)fd;
    (void)data;
    (void)flags;
    return (ssize_t)size;
}

static ssize_t fuzz_recv(int fd, void *out, size_t size, int flags)
{
    (void)fd;
    (void)flags;
    if (!fuzz_input_size)
        return 0;
    if (size > fuzz_input_size)
        size = fuzz_input_size;
    memcpy(out, fuzz_input, size);
    fuzz_input += size;
    fuzz_input_size -= size;
    return (ssize_t)size;
}

static int fuzz_close(int fd)
{
    (void)fd;
    return 0;
}

int nm_camera_socket_connect(const char *host, unsigned port, unsigned timeout_ms,
                             const atomic_bool *cancel)
{
    (void)host;
    (void)port;
    (void)timeout_ms;
    (void)cancel;
    int fd = fuzz_fd;
    fuzz_fd = -1;
    return fd;
}

int64_t nm_camera_now_us(void)
{
    fuzz_clock += 1000;
    return fuzz_clock;
}

bool nm_camera_md5(const uint8_t *data, size_t length, uint8_t out[16])
{
    uint8_t value = 0;
    for (size_t i = 0; i < length; ++i)
        value = (uint8_t)(value * 33U + data[i]);
    memset(out, value, 16);
    return true;
}

void nm_camera_random(uint8_t *out, size_t length)
{
    memset(out, 0x5a, length);
}

nm_camera_jpeg *nm_camera_jpeg_new(void)
{
    return calloc(1, sizeof(nm_camera_jpeg));
}

bool nm_camera_jpeg_packet(nm_camera_jpeg *jpeg, const uint8_t *packet, size_t length)
{
    (void)jpeg;
    (void)packet;
    (void)length;
    return false;
}

uint8_t *nm_camera_jpeg_take(nm_camera_jpeg *jpeg, size_t *length, unsigned *width,
                             unsigned *height)
{
    (void)jpeg;
    *length = 0;
    *width = 0;
    *height = 0;
    return NULL;
}

void nm_camera_jpeg_free(nm_camera_jpeg *jpeg)
{
    free(jpeg);
}

static int input_socket(const uint8_t *data, size_t size)
{
    fuzz_input = data;
    fuzz_input_size = size;
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!size || size > 32768)
        return 0;

    unsigned mode = data[0] % 7;
    ++data;
    --size;
    char *text = malloc(size + 1);
    if (!text)
        return 0;
    memcpy(text, data, size);
    text[size] = 0;

    if (mode == 0) {
        char host[256];
        unsigned port;
        (void)url_parse(text, host, sizeof(host), &port);
    } else if (mode == 1) {
        char out[1536];
        (void)header(text, "WWW-Authenticate", size ? data[0] % 10 : 0, out, sizeof(out));
        (void)header(text, "Content-Length", 0, out, sizeof(out));
        (void)header(text, "Session", 0, out, sizeof(out));
    } else if (mode == 2) {
        char out[1024];
        (void)parameter(text, "realm", out, sizeof(out));
        (void)parameter(text, "nonce", out, sizeof(out));
        (void)parameter(text, "qop", out, sizeof(out));
        (void)parameter(text, "opaque", out, sizeof(out));
    } else {
        int fd = input_socket(data, size);
        fuzz_clock = 0;
        if (mode == 3) {
            rtsp_session session = {.fd = fd, .end = 1000000, .sequence = size ? data[0] : 1};
            int status;
            (void)response(&session, &status);
        } else if (mode == 4 || mode == 5) {
            rtsp_session session = {.fd = fd,
                                    .end = 1000000,
                                    .username = "user",
                                    .password = "password"};
            strcpy(session.url, "rtsp://camera.test/live");
            strcpy(session.host, "camera.test");
            if (mode == 4)
                (void)request(&session, "DESCRIBE", session.url, "Accept: application/sdp\r\n");
            else
                (void)describe(&session);
        } else {
            fuzz_fd = fd;
            nm_camera_image image;
            (void)nm_camera_rtsp("rtsp://camera.test/live", "user", "password", 1000, NULL,
                                 &image);
            free(image.data);
            fuzz_fd = -1;
        }
    }
    free(text);
    return 0;
}
