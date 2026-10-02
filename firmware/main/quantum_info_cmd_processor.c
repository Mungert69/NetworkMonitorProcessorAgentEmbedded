#include "quantum_info_cmd_processor.h"
#include "quantum_algorithm_data.h"
#include "cmd_output.h"
#include "nm_json.h"
#include <ctype.h>
#include <stdio.h>
#include <strings.h>

const char *nm_quantum_info_cmd_help(void)
{
    return "Quantum Algorithm Info\nUsage: --algorithm <name-or-alias>\n"
           "Examples: --algorithm mlkem768; --algorithm kyber768; --algorithm dilithium3; "
           "--algorithm x25519mlkem768\n"
           "Partial searches match names, families, categories and keywords.\n"
           "Metadata follows the .NET algorithm catalog; information availability does not imply "
           "this firmware can execute that algorithm.\n";
}
bool nm_quantum_info_cmd_parse(const char *arguments, nm_quantum_info_command *request,
                               const char **error)
{
    if (!request || !error)
        return false;
    *request = (nm_quantum_info_command){0};
    *error = "Algorithm name is required. Try --algorithm mlkem768";
    if (!arguments || strlen(arguments) > 4096)
        return false;
    const char *cursor = arguments;
    char key[256], value[128];
    if (!nm_cmd_argument_token(&cursor, key, sizeof(key)))
        return false;
    char *name = key + (key[0] == '-' ? (key[1] == '-' ? 2 : 1) : 0);
    char *equals = strchr(name, '=');
    if (equals)
        *equals = 0;
    if (strcasecmp(name, "algorithm"))
        return false;
    if (equals) {
        if (strlen(equals + 1) >= sizeof(value))
            return false;
        memcpy(value, equals + 1, strlen(equals + 1) + 1);
    } else if (!nm_cmd_argument_token(&cursor, value, sizeof(value)))
        return false;
    if (!*value || !nm_cmd_argument_token(&cursor, key, sizeof(key)) || *key)
        return false;
    memcpy(request->query, value, strlen(value) + 1);
    *error = NULL;
    return true;
}

static const char *text(yyjson_mut_val *record, const char *name)
{
    const char *value = yyjson_mut_get_str(yyjson_mut_obj_get(record, name));
    return value ? value : "";
}
static bool canonical(const char *input, char *output, size_t capacity)
{
    size_t used = 0;
    for (; *input; ++input) {
        unsigned char c = (unsigned char)*input;
        if (!isalnum(c))
            continue;
        if (used + 1 >= capacity)
            return false;
        output[used++] = (char)tolower(c);
    }
    output[used] = 0;
    return true;
}
static void query_alias(char *key, size_t capacity)
{
    if (!strncmp(key, "kyber", 5)) {
        memcpy(key, "mlkem", 5);
    } else if (!strcmp(key, "dilithium2"))
        snprintf(key, capacity, "mldsa44");
    else if (!strcmp(key, "dilithium3"))
        snprintf(key, capacity, "mldsa65");
    else if (!strcmp(key, "dilithium5"))
        snprintf(key, capacity, "mldsa87");
    else if (!strncmp(key, "sphincs", 7)) {
        memmove(key + 6, key + 7, strlen(key + 7) + 1);
        memcpy(key, "slhdsa", 6);
    }
}
static bool contains(const char *haystack, const char *query)
{
    size_t length = strlen(query);
    for (; *haystack; ++haystack)
        if (!strncasecmp(haystack, query, length))
            return true;
    return false;
}
static bool matches(yyjson_mut_val *record, const char *raw, const char *key)
{
    const char *fields[] = {"algorithmName", "family", "category"};
    char candidate[512];
    for (size_t i = 0; i < 3; ++i) {
        const char *value = text(record, fields[i]);
        if (contains(value, raw) ||
            (canonical(value, candidate, sizeof(candidate)) && strstr(candidate, key)))
            return true;
    }
    yyjson_mut_val *items = yyjson_mut_obj_get(record, "keywords"), *item;
    size_t i, n;
    yyjson_mut_arr_foreach(items, i, n, item)
    {
        const char *value = yyjson_mut_get_str(item);
        if (value && (contains(value, raw) ||
                      (canonical(value, candidate, sizeof(candidate)) && strstr(candidate, key))))
            return true;
    }
    return false;
}
static void optional_line(nm_cmd_output *output, yyjson_mut_val *record, const char *field,
                          const char *label)
{
    const char *value = text(record, field);
    if (*value)
        nm_cmd_output_append(output, "%s: %s\n", label, value);
}
static void size_line(nm_cmd_output *output, yyjson_mut_val *sizes, const char *field,
                      const char *label)
{
    yyjson_mut_val *value = yyjson_mut_obj_get(sizes, field);
    if (!yyjson_mut_is_uint(value) || yyjson_mut_get_uint(value) > INT32_MAX)
        return;
    uint64_t bytes = yyjson_mut_get_uint(value), hundredths = (bytes * 100 + 512) / 1024;
    char kib[32];
    snprintf(kib, sizeof(kib), "%llu.%02llu", (unsigned long long)(hundredths / 100),
             (unsigned long long)(hundredths % 100));
    size_t length = strlen(kib);
    while (length && kib[length - 1] == '0')
        kib[--length] = 0;
    if (length && kib[length - 1] == '.')
        kib[--length] = 0;
    nm_cmd_output_append(output, "  %s: %llu bytes (~%s KiB)\n", label, (unsigned long long)bytes,
                         kib);
}
static nm_cmd_result format_record(yyjson_mut_val *record)
{
    nm_cmd_output output;
    nm_cmd_output_init(&output, 8192);
    nm_cmd_output_append(&output, "Algorithm: %s\nFamily / Category: %s / %s\n",
                         text(record, "algorithmName"), text(record, "family"),
                         text(record, "category"));
    optional_line(&output, record, "nistStatus", "NIST Status");
    if (*text(record, "securityLevel")) {
        nm_cmd_output_append(&output, "Security: %s", text(record, "securityLevel"));
        yyjson_mut_val *category = yyjson_mut_obj_get(record, "securityCategory");
        if (yyjson_mut_is_uint(category))
            nm_cmd_output_append(&output, " (Category %llu)",
                                 (unsigned long long)yyjson_mut_get_uint(category));
        nm_cmd_output_append(&output, "\n");
    }
    optional_line(&output, record, "variant", "Variant");
    if (contains(text(record, "category"), "Hybrid")) {
        optional_line(&output, record, "baseAlgorithm", "Hybrid Base");
        optional_line(&output, record, "classicalAlgorithm", "Hybrid Classical");
        optional_line(&output, record, "sizeImpactNote", "Size Note");
    }
    yyjson_mut_val *sizes = yyjson_mut_obj_get(record, "sizes");
    if (yyjson_mut_is_uint(yyjson_mut_obj_get(sizes, "encapsulationKeyBytes")) ||
        yyjson_mut_is_uint(yyjson_mut_obj_get(sizes, "decapsulationKeyBytes")) ||
        yyjson_mut_is_uint(yyjson_mut_obj_get(sizes, "ciphertextBytes"))) {
        nm_cmd_output_append(&output, "Sizes (KEM):\n");
        size_line(&output, sizes, "encapsulationKeyBytes", "Encapsulation key (pub)");
        size_line(&output, sizes, "decapsulationKeyBytes", "Decapsulation key (priv)");
        size_line(&output, sizes, "ciphertextBytes", "Ciphertext");
        size_line(&output, sizes, "sharedSecretBytes", "Shared secret");
    }
    if (yyjson_mut_is_uint(yyjson_mut_obj_get(sizes, "publicKeyBytes")) ||
        yyjson_mut_is_uint(yyjson_mut_obj_get(sizes, "privateKeyBytes")) ||
        yyjson_mut_is_uint(yyjson_mut_obj_get(sizes, "signatureBytes"))) {
        nm_cmd_output_append(&output, "Sizes (Signature):\n");
        size_line(&output, sizes, "publicKeyBytes", "Public key");
        size_line(&output, sizes, "privateKeyBytes", "Private key");
        size_line(&output, sizes, "signatureBytes", "Signature");
    }
    if (*text(record, "description"))
        nm_cmd_output_append(&output, "\nDescription:\n  %s\n", text(record, "description"));
    yyjson_mut_val *items = yyjson_mut_obj_get(record, "implementationNotes"), *item;
    size_t i, n;
    if (yyjson_mut_arr_size(items))
        nm_cmd_output_append(&output, "\nImplementation Notes:\n");
    yyjson_mut_arr_foreach(items, i, n, item)
    {
        const char *value = yyjson_mut_get_str(item);
        if (value)
            nm_cmd_output_append(&output, "  • %s\n", value);
    }
    if (*text(record, "advisory"))
        nm_cmd_output_append(&output, "\nAdvisory:\n  %s\n", text(record, "advisory"));
    items = yyjson_mut_obj_get(record, "references");
    if (yyjson_mut_arr_size(items))
        nm_cmd_output_append(&output, "\nReferences:\n");
    yyjson_mut_arr_foreach(items, i, n, item)
    {
        nm_cmd_output_append(&output, "  • [%s] %s%s%s%s%s\n",
                             *text(item, "type") ? text(item, "type") : "Ref", text(item, "id"),
                             *text(item, "id") ? " — " : "", text(item, "title"),
                             *text(item, "url") ? " — " : "", text(item, "url"));
    }
    return nm_cmd_output_finish(&output, true);
}
typedef struct {
    yyjson_mut_doc *doc;
    yyjson_mut_val *record;
} info_match;
static int compare_records(const void *left, const void *right)
{
    const info_match *a = left, *b = right;
    const char *fields[] = {"category", "family", "algorithmName"};
    for (size_t i = 0; i < 3; ++i) {
        int result = strcmp(text(a->record, fields[i]), text(b->record, fields[i]));
        if (result)
            return result;
    }
    return 0;
}
nm_cmd_result nm_quantum_info_cmd_run(const nm_quantum_info_command *request,
                                      const atomic_bool *cancellation)
{
    if (!request)
        return (nm_cmd_result){.output = nm_bulk_strdup("Invalid algorithm info request")};
    char key[128], candidate[256];
    if (!canonical(request->query, key, sizeof(key)) || !*key)
        return (nm_cmd_result){
            .output = nm_bulk_strdup("Algorithm name is required. Try --algorithm mlkem768")};
    query_alias(key, sizeof(key));
    const size_t total = sizeof(nm_quantum_algorithm_data) / sizeof(nm_quantum_algorithm_data[0]);
    info_match *found = nm_bulk_calloc(total, sizeof(*found));
    if (!found)
        return (nm_cmd_result){0};
    size_t count = 0;
    nm_cmd_result result = {0};
    for (size_t i = 0; i < total; ++i) {
        if (cancellation && atomic_load(cancellation)) {
            result.output = nm_bulk_strdup("Quantum algorithm info canceled or timed out.\n");
            goto done;
        }
        const char *json = nm_quantum_algorithm_data[i];
        yyjson_mut_doc *doc = nm_json_read(json, strlen(json));
        if (!doc)
            goto done;
        yyjson_mut_val *record = yyjson_mut_doc_get_root(doc);
        if (canonical(text(record, "algorithmName"), candidate, sizeof(candidate)) &&
            !strcmp(candidate, key)) {
            result = format_record(record);
            yyjson_mut_doc_free(doc);
            goto done;
        }
        if (matches(record, request->query, key))
            found[count++] = (info_match){doc, record};
        else
            yyjson_mut_doc_free(doc);
    }
    if (count == 1)
        result = format_record(found[0].record);
    else {
        nm_cmd_output output;
        nm_cmd_output_init(&output, 8192);
        if (!count)
            nm_cmd_output_append(&output, "No algorithms found matching '%s'.", request->query);
        else {
            nm_cmd_output_append(&output,
                                 "\nMultiple algorithms matched '%s'. Please specify one of:\n",
                                 request->query);
            qsort(found, count, sizeof(*found), compare_records);
            for (size_t i = 0; i < count; ++i)
                nm_cmd_output_append(
                    &output, "- %s  (%s / %s)\n", text(found[i].record, "algorithmName"),
                    text(found[i].record, "category"), text(found[i].record, "family"));
        }
        result = nm_cmd_output_finish(&output, false);
    }
done:
    for (size_t i = 0; i < count; ++i)
        yyjson_mut_doc_free(found[i].doc);
    free(found);
    return result;
}
