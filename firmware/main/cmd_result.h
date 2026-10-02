#ifndef NM_CMD_RESULT_H
#define NM_CMD_RESULT_H
#include <stdbool.h>
#include <stdatomic.h>
typedef struct {
    bool success;
    char *output; /* Owned PSRAM/libc allocation, released with free(). */
} nm_cmd_result;
#endif
