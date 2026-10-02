#include "cmd_processor_message.h"
#include <limits.h>
#include <stdio.h>

bool nm_cmd_message_output(yyjson_mut_doc *doc, const char *output, bool success, bool ack)
{
    yyjson_mut_val *root = yyjson_mut_doc_get_root(doc);
    return output && nm_json_put_str(doc, root, "ScanCommandOutput", output) &&
           nm_json_put(doc, root, "ScanCommandSuccess", yyjson_mut_bool(doc, success)) &&
           (!ack || nm_json_put(doc, root, "IsAck", yyjson_mut_bool(doc, true)));
}

static bool integer(yyjson_mut_val *root, const char *key, int fallback, int *value)
{
    yyjson_mut_val *v = yyjson_mut_obj_get(root, key);
    if (!v) {
        *value = fallback;
        return true;
    }
    if (!yyjson_mut_is_int(v))
        return false;
    if (yyjson_mut_is_uint(v) && yyjson_mut_get_uint(v) > INT_MAX)
        return false;
    int64_t n = yyjson_mut_get_sint(v);
    if (n < INT_MIN || n > INT_MAX)
        return false;
    *value = (int)n;
    return true;
}

bool nm_cmd_message_format(yyjson_mut_doc *doc, const char *output, bool success,
                           unsigned default_limit)
{
    yyjson_mut_val *root = yyjson_mut_doc_get_root(doc);
    int limit, page;
    if (!output || !default_limit || default_limit > INT_MAX ||
        !integer(root, "LineLimit", -1, &limit) || !integer(root, "Page", 1, &page))
        return false;
    if (limit == -1)
        limit = (int)default_limit;
    if (limit != -2 && limit <= 0)
        return false;
    size_t length = strlen(output);
    if (length > 32768)
        return false;
    char *copy = nm_bulk_strdup(length ? output : "The cmd processor gave no output");
    char *formatted = nm_bulk_malloc(length + 512);
    if (!copy || !formatted) {
        free(copy);
        free(formatted);
        return false;
    }
    char *lines[256];
    unsigned count = 0;
    char *cursor = copy;
    while (*cursor) {
        while (*cursor == '\r' || *cursor == '\n')
            ++cursor;
        if (!*cursor)
            break;
        if (count == 256) {
            free(copy);
            free(formatted);
            return false;
        }
        lines[count++] = cursor;
        while (*cursor && *cursor != '\r' && *cursor != '\n')
            ++cursor;
        if (*cursor)
            *cursor++ = 0;
    }
    if (!count)
        lines[count++] = "The cmd processor gave no output";
    unsigned pages = limit == -2 ? 1 : (count + (unsigned)limit - 1) / (unsigned)limit;
    if (page < 1)
        page = 1;
    else if ((unsigned)page > pages)
        page = (int)pages;
    unsigned start = limit == -2 ? 0 : ((unsigned)page - 1) * (unsigned)limit;
    unsigned end = limit == -2 || (unsigned)limit > count - start ? count : start + (unsigned)limit;
    size_t used = 0;
    for (unsigned i = start; i < end; ++i) {
        size_t n = strlen(lines[i]);
        memcpy(formatted + used, lines[i], n);
        used += n;
        formatted[used++] = '\n';
    }
    if (limit != -2 && count > (unsigned)limit) {
        int n = snprintf(formatted + used, length + 512 - used,
                         "[Showing page %d of %u. Total lines: %u.]\n", page, pages, count);
        if (n < 0 || (size_t)n >= length + 512 - used)
            goto fail;
        used += (size_t)n;
        if ((unsigned)page < pages) {
            n = snprintf(formatted + used, length + 512 - used,
                         "[Output truncated to %d lines per page. Choose another page or refine "
                         "the query for less data.]\n",
                         limit);
            if (n < 0 || (size_t)n >= length + 512 - used)
                goto fail;
            used += (size_t)n;
        }
    }
    formatted[used] = 0;
    /* CmdProcessor.SendMessage serializes the output string once, removes its
     * quotes, then places that escaped text inside ProcessorScanDataObj. */
    yyjson_mut_val *text = yyjson_mut_strncpy(doc, formatted, used);
    size_t encoded_length = 0;
    char *encoded = text ? nm_json_write(text, 0, &encoded_length) : NULL;
    bool ok = encoded && encoded_length >= 2;
    if (ok) {
        encoded[encoded_length - 1] = 0;
        ok = nm_cmd_message_output(doc, encoded + 1, success, false) &&
             nm_json_put(doc, root, "LineLimit", yyjson_mut_sint(doc, limit)) &&
             nm_json_put(doc, root, "Page", yyjson_mut_sint(doc, page));
    }
    free(encoded);
    free(copy);
    free(formatted);
    return ok;
fail:
    free(copy);
    free(formatted);
    return false;
}
