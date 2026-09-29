#ifndef NM_ENDPOINT_RESOURCE_H
#define NM_ENDPOINT_RESOURCE_H
#include <errno.h>
#include <stdbool.h>

/* Resource exhaustion is local, unlike refusal/unreachability/timeout. */
static inline bool nm_endpoint_resource_errno(int error)
{
    return error == ENOMEM || error == ENOBUFS || error == EMFILE || error == ENFILE;
}
#endif
