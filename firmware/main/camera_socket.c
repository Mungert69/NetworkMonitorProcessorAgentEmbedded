#include "camera_rtsp.h"
#include "camera_http.h"
#include "endpoint_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
int nm_camera_socket_connect(const char *host, unsigned port, unsigned timeout_ms,
                             const atomic_bool *cancel)
{
    if (!timeout_ms || (cancel && atomic_load(cancel)))
        return -1;
    int64_t end = nm_camera_now_us() + (int64_t)timeout_ms * 1000;
    struct addrinfo *addresses = NULL;
    unsigned dns_budget = timeout_ms > 1000 ? 1000 : timeout_ms;
    if (nm_endpoint_resolve(host, port, dns_budget, &addresses) != LOOKUP_OK)
        return -1;
    int fd = -1;
    for (struct addrinfo *a = addresses; a && nm_camera_now_us() < end; a = a->ai_next) {
        if (cancel && atomic_load(cancel))
            break;
        if (!a->ai_addr || a->ai_addrlen > sizeof(struct sockaddr_storage))
            continue;
        fd = socket(a->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0)
            break;
        if (fd >= FD_SETSIZE) {
            close(fd);
            fd = -1;
            continue;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(fd);
            fd = -1;
            continue;
        }
        int rc = connect(fd, a->ai_addr, a->ai_addrlen);
        if (rc == 0)
            break;
        if (errno == EINPROGRESS) {
            while (nm_camera_now_us() < end && !(cancel && atomic_load(cancel))) {
                fd_set write_set;
                FD_ZERO(&write_set);
                FD_SET(fd, &write_set);
                struct timeval wait = {.tv_usec = 50000};
                rc = select(fd + 1, NULL, &write_set, NULL, &wait);
                if (rc > 0) {
                    int error = 0;
                    socklen_t n = sizeof(error);
                    if (!getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &n) && !error)
                        rc = 0;
                    else
                        rc = -1;
                    break;
                }
                if (rc < 0 && errno != EINTR)
                    break;
                rc = -1;
            }
            if (rc == 0 && nm_camera_now_us() < end && !(cancel && atomic_load(cancel)))
                break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    return fd;
}
