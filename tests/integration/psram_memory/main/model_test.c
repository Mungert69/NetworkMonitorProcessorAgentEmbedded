/* Real typed model and production Brotli snapshot/NVS workload. */
#include "nm_esp.h"
#include "esp_heap_caps.h"
#include "esp_memory_utils.h"
#include "nvs.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void verify_compressed_blob(size_t expected_raw_size)
{
    nvs_handle_t handle;
    assert(nvs_open_from_partition("nmdata", "networkmonitor", NVS_READONLY, &handle) == ESP_OK);
    size_t stored_size = 0;
    assert(nvs_get_blob(handle, "monitoring", NULL, &stored_size) == ESP_OK);
    assert(stored_size > 12 && stored_size <= 512 * 1024);
    uint8_t *stored = nm_bulk_malloc(stored_size);
    assert(stored && esp_ptr_external_ram(stored));
    assert(nvs_get_blob(handle, "monitoring", stored, &stored_size) == ESP_OK);
    nvs_close(handle);
    static const uint8_t magic[8] = {'N', 'M', 'S', 'B', 1, '\r', '\n', 0};
    assert(memcmp(stored, magic, sizeof(magic)) == 0);
    uint32_t raw_size = (uint32_t)stored[8] | ((uint32_t)stored[9] << 8) |
                        ((uint32_t)stored[10] << 16) | ((uint32_t)stored[11] << 24);
    assert(raw_size == expected_raw_size);
    free(stored);
}

void run_model_test(void)
{
    assert(nm_esp_storage_init());
    nm_model live;
    assert(nm_model_open(&live, NULL, NULL, NULL, 50, 500));
    yyjson_mut_doc *doc = nm_json_new();
    assert(doc);
    yyjson_mut_val *hosts = yyjson_mut_arr(doc);
    assert(hosts);
    yyjson_mut_doc_set_root(doc, hosts);
    for (int32_t id = 100; id < 150; ++id) {
        yyjson_mut_val *host = yyjson_mut_obj(doc);
        assert(host);
        assert(yyjson_mut_obj_add_int(doc, host, "ID", id));
        assert(yyjson_mut_obj_add_bool(doc, host, "Enabled", true));
        assert(yyjson_mut_obj_add_str(doc, host, "Address", "example.test"));
        assert(yyjson_mut_obj_add_str(doc, host, "EndPointType", "http"));
        assert(yyjson_mut_obj_add_str(doc, host, "Username", ""));
        assert(yyjson_mut_obj_add_str(doc, host, "Password", ""));
        assert(yyjson_mut_arr_append(hosts, host));
    }
    const char *when = "2026-09-27T12:00:00Z";
    assert(nm_model_updates(&live, hosts, "synthetic", when));
    yyjson_mut_doc_free(doc);
    for (unsigned probe = 0; probe < 250; ++probe) {
        nm_model next;
        assert(nm_model_clone(&next, &live));
        assert(nm_model_probe(&next, 100 + probe % 50, probe % 3 != 0, 12, "OK", "synthetic result",
                              when, probe));
        doc = nm_model_encode(&next);
        assert(doc);
        size_t length = 0;
        char *encoded = nm_json_write(yyjson_mut_doc_get_root(doc), 0, &length);
        assert(encoded && length == strlen(encoded));
        assert(nm_esp_storage_save("monitoring", yyjson_mut_doc_get_root(doc)));
        verify_compressed_blob(length);
        yyjson_mut_doc *loaded = nm_esp_storage_load("monitoring");
        assert(loaded &&
               yyjson_mut_equals(yyjson_mut_doc_get_root(doc), yyjson_mut_doc_get_root(loaded)));
        nm_model restored;
        assert(nm_model_open(&restored, yyjson_mut_doc_get_root(loaded), NULL, NULL, 50, 500));
        assert(restored.hosts.count == 50 && restored.infos.count == 50);
        assert(restored.pings.count == probe + 1 && restored.sequence == next.sequence);
        nm_model_close(&restored);
        yyjson_mut_doc_free(loaded);
        free(encoded);
        yyjson_mut_doc_free(doc);
        nm_model_close(&live);
        live = next;
        assert(heap_caps_check_integrity_all(true));
        if (probe % 25 == 0)
            printf("MODEL probe=%u\n", probe);
    }
    nm_model_close(&live);
    puts("PSRAM_MODEL_INTEGRATION_PASS");
}
