/* Differential checks against tests/dotnet/EndpointParity's real .NET output.
 * No network or radio; crypto adapter is host-only, firmware uses PSA. */
#include "nm_esp.h"
#include "ble_metric.h"
#include "endpoint_status.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include "yyjson.h"

static const char *str(yyjson_val *object, const char *key)
{
    const char *value = yyjson_get_str(yyjson_obj_get(object, key));
    assert(value);
    return value;
}
static size_t hex(const char *text, uint8_t *out, size_t capacity)
{
    size_t size = strlen(text) / 2;
    assert(strlen(text) % 2 == 0 && size <= capacity);
    for (size_t i = 0; i < size; ++i) {
        unsigned value;
        assert(sscanf(text + i * 2, "%2x", &value) == 1);
        out[i] = (uint8_t)value;
    }
    return size;
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    yyjson_doc *doc = yyjson_read_file(argv[1], 0, NULL, NULL);
    assert(doc);
    yyjson_val *root = yyjson_doc_get_root(doc), *item;
    size_t i, count;
    yyjson_val *durations = yyjson_obj_get(root, "DurationCases");
    assert(yyjson_arr_size(durations) == 11);
    yyjson_arr_foreach(durations, i, count, item)
    {
        const char *type = str(item, "Type");
        assert(nm_endpoint_duration_scale(type) == yyjson_get_num(yyjson_obj_get(item, "Scale")));
        assert(nm_endpoint_timeout_multiplier(type) ==
               yyjson_get_uint(yyjson_obj_get(item, "TimeoutMultiplier")));
        yyjson_val *samples = yyjson_obj_get(item, "Samples"), *sample;
        size_t s, total;
        yyjson_arr_foreach(samples, s, total, sample)
        {
            nm_esp_result result = {
                .ok = true,
                .elapsed_ms = (unsigned)yyjson_get_uint(yyjson_obj_get(sample, "Elapsed"))};
            assert(nm_esp_result_sample(type, &result) ==
                   yyjson_get_uint(yyjson_obj_get(sample, "Sample")));
            result.ok = false;
            assert(nm_esp_result_sample(type, &result) == UINT16_MAX);
        }
        printf("PASS duration/timeout policy %s\n", type);
    }
    yyjson_val *ble = yyjson_obj_get(root, "BleCases");
    yyjson_arr_foreach(ble, i, count, item)
    {
        uint8_t payload[255], key[32];
        size_t length = hex(str(item, "Payload"), payload, sizeof(payload));
        size_t key_length = hex(str(item, "Key"), key, sizeof(key));
        const char *format = str(item, "Format"), *metric = str(item, "Metric");
        const nm_ble_decoder *decoder = nm_ble_decoder_find(format);
        nm_ble_metric_selection selected = {.requested = nm_ble_metric_canonical(metric)};
        char output[8192];
        bool ok = nm_ble_decoder_decode_metric(decoder, (nm_ble_bytes){payload, length},
                                               str(item, "PayloadType"), str(item, "Address"), key,
                                               key_length, output, sizeof(output), &selected);
        assert(ok == yyjson_get_bool(yyjson_obj_get(item, "DecodeOk")));
        assert(selected.matches == yyjson_get_uint(yyjson_obj_get(item, "Matches")));
        yyjson_val *value = yyjson_obj_get(item, "Value");
        assert(selected.available == !yyjson_is_null(value));
        if (selected.available)
            assert(fabs(selected.value - yyjson_get_num(value)) < 1e-7);
        uint16_t sample = 0;
        bool encoded =
            ok && selected.matches == 1 && selected.available &&
            nm_ble_metric_encode(nm_ble_metric_find(format, metric), selected.value, &sample);
        assert(encoded == yyjson_get_bool(yyjson_obj_get(item, "Encoded")));
        if (encoded) {
            assert(sample == yyjson_get_uint(yyjson_obj_get(item, "Sample")));
            nm_esp_result result = {
                .ok = true, .elapsed_ms = 70000, .sample = sample, .has_sample = true};
            assert(nm_esp_result_sample("blebroadcast", &result) == sample);
            result.ok = false;
            assert(nm_esp_result_sample("blebroadcast", &result) == UINT16_MAX);
        }
        printf("PASS .NET decoder vector %s\n", str(item, "Name"));
    }
    yyjson_val *http = yyjson_obj_get(root, "HttpStatuses");
    assert(yyjson_arr_size(http) == 900);
    yyjson_arr_foreach(http, i, count, item)
    {
        int code = (int)yyjson_get_uint(yyjson_obj_get(item, "Code"));
        nm_endpoint_status_result mapped =
            nm_endpoint_status("http", NM_ENDPOINT_SUCCESS, code, 123);
        assert(mapped.ok && mapped.rtt == 123 && !strcmp(mapped.status, str(item, "Status")));
    }
    yyjson_doc_free(doc);
    puts("endpoint policy/decoder contracts passed");
    return 0;
}
