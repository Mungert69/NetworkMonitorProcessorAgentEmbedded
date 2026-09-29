#include "probe_config.h"
#include "nm_json.h"
#include <assert.h>
#include <stdio.h>

int main(void)
{
    const char *operation_values[] = {NULL, "1", "4", "8", "0", "9", "-1", "1.5",
                                      "4.0", "null", "true", "\"4\"", "[]", "{}",
                                      "18446744073709551615"};
    for (unsigned i = 0; i < sizeof(operation_values) / sizeof(operation_values[0]); ++i) {
        char json[160];
        if (operation_values[i])
            snprintf(json, sizeof(json), "{\"MaxTaskQueueSize\":2,\"MaxOutstandingEndpointOperations\":%s}",
                     operation_values[i]);
        else
            snprintf(json, sizeof(json), "{\"MaxTaskQueueSize\":2}");
        yyjson_mut_doc *doc = nm_json_read(json, strlen(json));
        unsigned limit = 99, workers = 99;
        bool valid = nm_endpoint_operation_config_read(yyjson_mut_doc_get_root(doc), &limit);
        assert(valid == (i < 4));
        const unsigned expected_limits[] = {4, 1, 4, 8};
        assert(limit == (valid ? expected_limits[i] : 99));
        assert(nm_probe_config_read(yyjson_mut_doc_get_root(doc), &workers) && workers == 2);
        yyjson_mut_doc_free(doc);
    }
    assert(!nm_endpoint_operation_config_read(NULL, NULL));
    const char *cases[] = {"{}", "{\"MaxTaskQueueSize\":1}", "{\"MaxTaskQueueSize\":2}",
                           "{\"MaxTaskQueueSize\":8}"};
    const unsigned expected[] = {4, 1, 2, 8};
    for (unsigned i = 0; i < 4; ++i) {
        yyjson_mut_doc *doc = nm_json_read(cases[i], strlen(cases[i]));
        unsigned workers = 99;
        assert(nm_probe_config_read(yyjson_mut_doc_get_root(doc), &workers));
        assert(workers == expected[i]);
        yyjson_mut_doc_free(doc);
    }
    const char *invalid[] = {
        "0", "9", "-1", "1.5", "2.0", "null", "true", "\"8\"", "18446744073709551615", "[]", "{}"};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        char text[100];
        snprintf(text, sizeof(text), "{\"MaxTaskQueueSize\":%s}", invalid[i]);
        yyjson_mut_doc *doc = nm_json_read(text, strlen(text));
        unsigned workers = 99;
        assert(!nm_probe_config_read(yyjson_mut_doc_get_root(doc), &workers));
        assert(workers == 99);
        yyjson_mut_doc_free(doc);
    }
    assert(!nm_probe_config_read(NULL, NULL));
    puts("probe config defaults, boundaries and invalid inputs passed");
}
