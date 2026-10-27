#include "camera_xml.h"
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static bool append(char *out, size_t cap, size_t *used, const char *text, size_t n)
{
    if (n >= cap || *used >= cap - n)
        return false;
    memcpy(out + *used, text, n);
    *used += n;
    out[*used] = 0;
    return true;
}
bool nm_camera_xml_escape(const char *in, char *out, size_t cap)
{
    size_t n = 0;
    if (!cap)
        return false;
    *out = 0;
    for (; *in; ++in) {
        const char *s = *in == '&'    ? "&amp;"
                        : *in == '<'  ? "&lt;"
                        : *in == '>'  ? "&gt;"
                        : *in == '"'  ? "&quot;"
                        : *in == '\'' ? "&apos;"
                                      : NULL;
        if ((unsigned char)*in < 32 || !append(out, cap, &n, s ? s : in, s ? strlen(s) : 1))
            return false;
    }
    return true;
}
static bool decode(const char *in, size_t length, char *out, size_t cap)
{
    size_t n = 0;
    if (!cap)
        return false;
    *out = 0;
    for (size_t i = 0; i < length; ++i) {
        if (in[i] != '&') {
            if ((!isspace((unsigned char)in[i]) && (unsigned char)in[i] < 32) ||
                !append(out, cap, &n, in + i, 1))
                return false;
            continue;
        }
        size_t j = i + 1;
        while (j < length && j - i < 12 && in[j] != ';')
            ++j;
        if (j == length || in[j] != ';')
            return false;
        const char *entities[] = {"amp;", "lt;", "gt;", "quot;", "apos;"};
        const char decoded[] = "&<>\"'";
        bool found = false;
        for (unsigned k = 0; k < 5; ++k)
            if (strlen(entities[k]) == j - i && !memcmp(in + i + 1, entities[k], j - i)) {
                if (!append(out, cap, &n, decoded + k, 1))
                    return false;
                found = true;
                break;
            }
        if (!found && in[i + 1] == '#') {
            char number[12];
            size_t start = i + 2;
            int base = 10;
            if (start < j && in[start] == 'x') {
                ++start;
                base = 16;
            }
            size_t len = j - start;
            if (!len || len >= sizeof(number))
                return false;
            memcpy(number, in + start, len);
            number[len] = 0;
            for (size_t k = 0; k < len; ++k)
                if (!(base == 16 ? isxdigit((unsigned char)number[k])
                                 : isdigit((unsigned char)number[k])))
                    return false;
            unsigned long code = strtoul(number, NULL, base);
            if (!code || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff) ||
                (code < 32 && code != 9 && code != 10 && code != 13))
                return false;
            char utf[4];
            size_t bytes;
            if (code < 128) {
                utf[0] = (char)code;
                bytes = 1;
            } else if (code < 2048) {
                utf[0] = (char)(0xc0 | (code >> 6));
                utf[1] = (char)(0x80 | (code & 63));
                bytes = 2;
            } else if (code < 65536) {
                utf[0] = (char)(0xe0 | (code >> 12));
                utf[1] = (char)(0x80 | ((code >> 6) & 63));
                utf[2] = (char)(0x80 | (code & 63));
                bytes = 3;
            } else {
                utf[0] = (char)(0xf0 | (code >> 18));
                utf[1] = (char)(0x80 | ((code >> 12) & 63));
                utf[2] = (char)(0x80 | ((code >> 6) & 63));
                utf[3] = (char)(0x80 | (code & 63));
                bytes = 4;
            }
            if (!append(out, cap, &n, utf, bytes))
                return false;
            found = true;
        }
        if (!found)
            return false;
        i = j;
    }
    return true;
}
static void spaces(const char **p)
{
    while (isspace((unsigned char)**p))
        ++*p;
}
static bool name(const char **p, char out[96])
{
    size_t n = 0;
    if (!(isalpha((unsigned char)**p) || **p == '_'))
        return false;
    while (isalnum((unsigned char)**p) || **p == '_' || **p == '-' || **p == '.' || **p == ':') {
        if (n == 95)
            return false;
        out[n++] = *(*p)++;
    }
    out[n] = 0;
    return true;
}
static const char *local_name(const char *name)
{
    const char *colon = strrchr(name, ':');
    return colon ? colon + 1 : name;
}
bool nm_camera_xml_value(const char *xml, const char *local, const char *attribute, unsigned index,
                         char *out, size_t cap)
{
    if (!xml || !local || !out || !cap || strlen(xml) > 32768)
        return false;
    char stack[24][96];
    unsigned depth = 0, matches = 0;
    bool found = false, root = false, closed = false;
    const char *p = xml, *text = NULL;
    unsigned text_depth = 0;
    *out = 0;
    while (*p) {
        if (*p != '<') {
            if (!depth && !isspace((unsigned char)*p))
                return false;
            ++p;
            continue;
        }
        if (!strncmp(p, "<!--", 4)) {
            const char *end = strstr(p + 4, "--");
            if (!end || strncmp(end, "-->", 3))
                return false;
            if (text)
                return false;
            p = end + 3;
            continue;
        }
        if (!strncmp(p, "<?xml ", 6) && !root) {
            const char *end = strstr(p + 6, "?>");
            if (!end)
                return false;
            p = end + 2;
            continue;
        }
        ++p;
        bool closing = *p == '/';
        if (closing)
            ++p;
        char tag[96];
        if (!name(&p, tag))
            return false;
        if (closing) {
            spaces(&p);
            if (*p++ != '>' || !depth || strcmp(stack[depth - 1], tag))
                return false;
            if (text && text_depth == depth) {
                const char *end;
                /* Find the opening '<' of this closing tag, allowing whitespace. */
                end = p - 1;
                while (end > text && *end != '<')
                    --end;
                while (text < end && isspace((unsigned char)*text))
                    ++text;
                while (end > text && isspace((unsigned char)end[-1]))
                    --end;
                if (!decode(text, (size_t)(end - text), out, cap))
                    return false;
                found = true;
                text = NULL;
            }
            if (!--depth)
                closed = true;
            continue;
        }
        if (closed || depth == 24 || text)
            return false;
        root = true;
        bool match = !strcmp(local_name(tag), local), selected = false;
        if (match)
            selected = matches++ == index;
        strcpy(stack[depth++], tag);
        spaces(&p);
        while (*p && *p != '>' && *p != '/') {
            char attr[96];
            if (!name(&p, attr))
                return false;
            spaces(&p);
            if (*p++ != '=')
                return false;
            spaces(&p);
            char quote = *p++;
            if (quote != '\'' && quote != '"')
                return false;
            const char *start = p;
            while (*p && *p != quote) {
                if (*p == '<')
                    return false;
                ++p;
            }
            if (!*p)
                return false;
            if (selected && attribute && !strcmp(local_name(attr), attribute)) {
                if (!decode(start, (size_t)(p - start), out, cap))
                    return false;
                found = true;
            }
            ++p;
            if (*p != '>' && *p != '/' && !isspace((unsigned char)*p))
                return false;
            spaces(&p);
        }
        bool empty = *p == '/';
        if (empty)
            ++p;
        if (*p++ != '>')
            return false;
        if (empty) {
            if (!--depth)
                closed = true;
        } else if (selected && !attribute) {
            text = p;
            text_depth = depth;
        }
    }
    if (depth || !closed || !found) {
        *out = 0;
        return false;
    }
    return true;
}
