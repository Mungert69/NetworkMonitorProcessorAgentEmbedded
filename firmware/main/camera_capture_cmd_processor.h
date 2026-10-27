#ifndef NM_CAMERA_CAPTURE_CMD_PROCESSOR_H
#define NM_CAMERA_CAPTURE_CMD_PROCESSOR_H
#include "cmd_arguments.h"
#include "cmd_result.h"
/* Owned, bounded copies: safe to transfer to the command worker. */
typedef struct {
    char address[1024], username[128], password[256], profile_token[128];
    char rtsp_path[512];
    unsigned onvif_port, rtsp_port, timeout_ms;
    bool high_detail, rtsp;
} nm_camera_command;
const char *nm_camera_cmd_help(void);
bool nm_camera_cmd_parse(const char *, nm_camera_command *, const char **error);
/* Transfers owned output/JPEG in result; caller releases both with free(). */
nm_cmd_result nm_camera_cmd_run(const nm_camera_command *, const atomic_bool *);
#endif
