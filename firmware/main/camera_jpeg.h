#ifndef NM_CAMERA_JPEG_H
#define NM_CAMERA_JPEG_H
#include "cmd_result.h"
typedef struct nm_camera_jpeg nm_camera_jpeg;
/* Single owner. RFC 2435 JPEG over RTP, bounded to NM_CMD_RAW_MAX. */
nm_camera_jpeg *nm_camera_jpeg_new(void);
/* Borrows RTP packet. Returns true only when a complete contiguous frame is
 * available. Invalid/lost/oversized frames are discarded; a later frame can start. */
bool nm_camera_jpeg_packet(nm_camera_jpeg *, const uint8_t *, size_t);
/* Transfers JPEG allocation on success; decoder remains releasable. */
uint8_t *nm_camera_jpeg_take(nm_camera_jpeg *, size_t *, unsigned *, unsigned *);
void nm_camera_jpeg_free(nm_camera_jpeg *);
#endif
