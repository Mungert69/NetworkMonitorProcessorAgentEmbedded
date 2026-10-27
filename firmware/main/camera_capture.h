#ifndef NM_CAMERA_CAPTURE_H
#define NM_CAMERA_CAPTURE_H
#include "camera_capture_cmd_processor.h"
/* Native ONVIF/HTTP adapter. No MQTT/state access. Owned result allocations. */
nm_cmd_result nm_camera_capture(const nm_camera_command *, const atomic_bool *);
#endif
