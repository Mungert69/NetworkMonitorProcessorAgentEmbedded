#include "endpoint_internal.h"
#include "endpoint_resource.h"
#include "esp_timer.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

nm_esp_result nm_endpoint_check_tcp(const char *host, unsigned port, unsigned timeout)
{
    struct addrinfo *addresses = NULL;
    int64_t deadline_start = esp_timer_get_time();
    lookup_result lookup = nm_endpoint_resolve(host, port ? port : 443, timeout, &addresses);
    if (lookup != LOOKUP_OK)
        return nm_endpoint_lookup_failure("rawconnect", lookup,
                                          nm_endpoint_elapsed(deadline_start));
    /* RTT excludes name resolution as in SocketConnect. The execution budget
     * still includes it, and is shared by all address attempts. */
    int64_t start = esp_timer_get_time();
    bool connected = false, timed_out = false;
    int last_error = 0;
    for (const struct addrinfo *address = addresses; address; address = address->ai_next) {
        unsigned budget = nm_endpoint_remaining(deadline_start, timeout);
        if (!budget) {
            timed_out = true;
            break;
        }
        int fd = socket(address->ai_family, SOCK_STREAM, 0);
        if (fd < 0) {
            last_error = errno;
            if (nm_endpoint_resource_errno(last_error))
                break;
            continue;
        }
        /* lwIP's private fd_set indexes fd - LWIP_SOCKET_OFFSET; its
         * FD_SETSIZE alone is not the maximum descriptor number. */
#ifdef LWIP_SELECT_MAXNFDS
        int select_limit = LWIP_SELECT_MAXNFDS;
#else
        int select_limit = FD_SETSIZE;
#endif
        if (fd >= select_limit) {
            last_error = EMFILE;
            close(fd);
            continue;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            last_error = errno;
            close(fd);
            continue;
        }
        int rc = connect(fd, address->ai_addr, address->ai_addrlen);
        if (rc == 0)
            connected = true;
        else {
            last_error = errno;
            if (last_error == EINPROGRESS || last_error == EWOULDBLOCK) {
                for (;;) {
                    budget = nm_endpoint_remaining(deadline_start, timeout);
                    if (!budget) {
                        timed_out = true;
                        break;
                    }
                    fd_set writable;
                    FD_ZERO(&writable);
                    FD_SET(fd, &writable);
                    struct timeval wait = {.tv_sec = budget / 1000,
                                           .tv_usec = (budget % 1000) * 1000};
                    rc = select(fd + 1, NULL, &writable, NULL, &wait);
                    if (rc < 0 && errno == EINTR)
                        continue;
                    if (rc == 0) {
                        timed_out = true;
                        break;
                    }
                    if (rc < 0) {
                        last_error = errno;
                        break;
                    }
                    int error = 0;
                    socklen_t length = sizeof(error);
                    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0)
                        last_error = errno;
                    else {
                        last_error = error;
                        connected = error == 0;
                    }
                    break;
                }
            }
            if (last_error == ETIMEDOUT)
                timed_out = true;
        }
        close(fd);
        if (connected)
            break;
    }
    freeaddrinfo(addresses);
    if (!connected && nm_endpoint_resource_errno(last_error))
        return nm_endpoint_local_failure(nm_endpoint_elapsed(start), strerror(last_error));
    return nm_endpoint_result("rawconnect",
                              connected   ? NM_ENDPOINT_SUCCESS
                              : timed_out ? NM_ENDPOINT_TIMEOUT
                                          : NM_ENDPOINT_EXCEPTION,
                              0, nm_endpoint_elapsed(start),
                              timed_out    ? "Connection timed out."
                              : last_error ? strerror(last_error)
                                           : "TCP connection failed");
}
