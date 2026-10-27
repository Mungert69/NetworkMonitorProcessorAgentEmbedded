#ifndef NM_CMD_PROCESSOR_MESSAGE_H
#define NM_CMD_PROCESSOR_MESSAGE_H
#include "nm_json.h"
#include "cmd_result.h"
/* Mutates an owned response copy, retaining correlation/unknown fields. */
bool nm_cmd_message_output(yyjson_mut_doc *, const char *, bool success, bool ack);
/* Adds .NET byte[] base64 and metadata; empty result clears stale input data. */
bool nm_cmd_message_raw(yyjson_mut_doc *, const nm_cmd_result *);
bool nm_cmd_message_format(yyjson_mut_doc *, const char *, bool success, unsigned default_limit);
#endif
