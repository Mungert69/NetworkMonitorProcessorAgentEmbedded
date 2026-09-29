#include "fixtures.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#define main signature_test_main
#include "../../test_command_security.c"
#undef main
#include "freertos/semphr.h"
#include "psa/crypto.h"

static SemaphoreHandle_t completed;

static void crypto_worker(void *unused)
{
    (void)unused;
    /* NIST AES-GCM vector, also used by the production BLE host test. */
    static const uint8_t encrypted[] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                                        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
                                        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                                        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
    uint8_t key[16] = {0}, nonce[12] = {0}, output[32];
    for (unsigned iteration = 0; iteration < 10; ++iteration) {
        for (unsigned length = 12; length <= 16; ++length) {
            psa_algorithm_t algorithm = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, length);
            psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
            psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
            psa_set_key_bits(&attributes, 128);
            psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
            psa_set_key_algorithm(&attributes, algorithm);
            mbedtls_svc_key_id_t handle = PSA_KEY_ID_NULL;
            assert(psa_import_key(&attributes, key, sizeof(key), &handle) == PSA_SUCCESS);
            psa_reset_key_attributes(&attributes);
            size_t used = 0;
            assert(psa_aead_decrypt(handle, algorithm, nonce, sizeof(nonce), NULL, 0, encrypted,
                                    16 + length, output, sizeof(output), &used) == PSA_SUCCESS);
            assert(used == 16 && !memcmp(output, key, 16));
            uint8_t corrupt[sizeof(encrypted)];
            memcpy(corrupt, encrypted, sizeof(encrypted));
            corrupt[16 + length - 1] ^= 1;
            assert(psa_aead_decrypt(handle, algorithm, nonce, sizeof(nonce), NULL, 0, corrupt,
                                    16 + length, output, sizeof(output),
                                    &used) == PSA_ERROR_INVALID_SIGNATURE);
            assert(psa_destroy_key(handle) == PSA_SUCCESS);
        }
        vTaskDelay(1);
    }
    assert(xSemaphoreGive(completed) == pdTRUE);
    vTaskDelete(NULL);
}

void app_main(void)
{
    char *args[] = {"verifier", "embedded"};
    assert(signature_test_main(2, args) == 0);
    completed = xSemaphoreCreateCounting(8, 0);
    assert(completed);
    for (unsigned i = 0; i < 8; ++i)
        assert(xTaskCreate(crypto_worker, "crypto-test", 8192, NULL, 5, NULL) == pdPASS);
    for (unsigned i = 0; i < 8; ++i)
        assert(xSemaphoreTake(completed, pdMS_TO_TICKS(120000)) == pdTRUE);
    /* Workers no longer use the semaphore after give. Keep it for test lifetime. */
    puts("PSA concurrent GCM: 8 workers verified 12-16 byte tags and rejected tampering");
    puts("COMMAND_SECURITY_INTEGRATION_PASS");
    for (;;)
        vTaskDelay(pdMS_TO_TICKS(1000));
}
