#ifndef NM_CMD_RESULT_H
#define NM_CMD_RESULT_H
#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
/* Kept below the existing 128 KiB publication ceiling after base64/envelope. */
#define NM_CMD_RAW_MAX (64U * 1024U)
typedef struct {
    bool success;
    char *output;      /* Owned PSRAM/libc allocation, released with free(). */
    uint8_t *raw_data; /* Optional owned JPEG allocation; release with free(). */
    size_t raw_length;
    char raw_sha256[65];
} nm_cmd_result;
#endif
