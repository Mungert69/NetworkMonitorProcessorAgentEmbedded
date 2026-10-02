#include "cmd_arguments.h"
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
bool nm_cmd_argument_token(const char **input, char *out, size_t capacity)
{
    if (!input || !*input || !out || !capacity)
        return false;
    const char *p = *input;
    while (isspace((unsigned char)*p))
        ++p;
    size_t n = 0;
    char quote = 0;
    while (*p && (quote || !isspace((unsigned char)*p))) {
        char c = *p++;
        if (c == '\\' && *p)
            c = *p++;
        else if (c == '\'' || c == '"') {
            if (!quote) {
                quote = c;
                continue;
            }
            if (quote == c) {
                quote = 0;
                continue;
            }
        }
        if (n + 1 >= capacity)
            return false;
        out[n++] = c;
    }
    if (quote)
        return false;
    out[n] = 0;
    *input = p;
    return true;
}

bool nm_cmd_argument_number(const char *text, unsigned maximum, unsigned *value)
{
    if (!text || !text[0] || !value)
        return false;
    errno = 0;
    char *end;
    long n = strtol(text, &end, 10);
    if (errno || *end || n < 1 || (unsigned long)n > maximum)
        return false;
    *value = (unsigned)n;
    return true;
}

bool nm_cmd_argument_append(char *output, size_t capacity, size_t *used, const char *token)
{
    if (!output || !used || !token || *used >= capacity || capacity - *used < 4)
        return false;
    output[(*used)++] = ' ';
    output[(*used)++] = '"';
    for (; *token; ++token) {
        size_t need = (*token == '"' || *token == '\\') ? 2 : 1;
        if (capacity - *used < need + 2)
            return false;
        if (need == 2)
            output[(*used)++] = '\\';
        output[(*used)++] = *token;
    }
    output[(*used)++] = '"';
    output[*used] = 0;
    return true;
}

bool nm_cmd_ports_parse(const char *text, uint16_t *ports, size_t capacity, size_t *count,
                        bool ranges)
{
    if (!text || !ports || !count || strlen(text) > 1024)
        return false;
    char copy[1025];
    memcpy(copy, text, strlen(text) + 1);
    char *cursor = copy, *save = NULL;
    if (*cursor == '[') {
        size_t length = strlen(cursor);
        if (length < 2 || cursor[length - 1] != ']')
            return false;
        cursor[length - 1] = 0;
        ++cursor;
    }
    *count = 0;
    for (char *item = strtok_r(cursor, ",;: \t\r\n", &save); item;
         item = strtok_r(NULL, ",;: \t\r\n", &save)) {
        unsigned first, last;
        char *dash = strchr(item, '-');
        if (dash) {
            if (!ranges)
                return false;
            *dash++ = 0;
            if (!nm_cmd_argument_number(dash, 65535, &last))
                return false;
        }
        if (!nm_cmd_argument_number(item, 65535, &first))
            return false;
        if (!dash)
            last = first;
        if (last < first || last - first >= capacity)
            return false;
        for (unsigned port = first; port <= last; ++port) {
            bool duplicate = false;
            for (size_t i = 0; i < *count; ++i)
                duplicate |= ports[i] == port;
            if (duplicate)
                continue;
            if (*count == capacity)
                return false;
            ports[(*count)++] = (uint16_t)port;
        }
    }
    return true;
}
