#ifndef NM_CMD_PROCESSOR_MESSAGE_H
#define NM_CMD_PROCESSOR_MESSAGE_H
#include "nm_json.h"
/* Mutates an owned response copy, retaining correlation/unknown fields. */
bool nm_cmd_message_output(yyjson_mut_doc *, const char *, bool success, bool ack);
bool nm_cmd_message_format(yyjson_mut_doc *, const char *, bool success, unsigned default_limit);
#endif
