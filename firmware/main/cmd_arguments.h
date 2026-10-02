#ifndef NM_CMD_ARGUMENTS_H
#define NM_CMD_ARGUMENTS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Bounded CLI data parsing. Tokens are never passed to a shell. */
bool nm_cmd_argument_token(const char **input, char *out, size_t capacity);
bool nm_cmd_argument_number(const char *text, unsigned maximum, unsigned *value);
/* Bounded quoted token append for composing another validated parser's input. */
bool nm_cmd_argument_append(char *output, size_t capacity, size_t *used, const char *token);
/* Integers/ranges, deduplicated in input order. Separators match .NET lists;
 * ranges are optional for Nmap, not QuantumPortScanner. */
bool nm_cmd_ports_parse(const char *text, uint16_t *ports, size_t capacity, size_t *count,
                        bool ranges);
#endif
