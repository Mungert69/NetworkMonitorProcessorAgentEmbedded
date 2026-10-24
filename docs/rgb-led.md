# Onboard RGB LED — plain ESP32-S3

For the original **YD-ESP32-S3 plain board**, the onboard WS2812 RGB LED is
on **GPIO48**. The same RMT driver technique used on the screen board works;
only the GPIO changes. The LED expects **green, red, blue (GRB)** wire order,
not ordinary GPIO high/low or PWM.

| Board | RGB LED GPIO |
| --- | --- |
| YD-ESP32-S3 plain board used by RobinNet | 48 |
| Espressif ESP32-S3-DevKitC-1 initial version | 48 |
| Espressif ESP32-S3-DevKitC-1 v1.1 | 38 |
| LCDWIKI ES3C35P-compatible screen board | 40 |

N16R8 describes flash/PSRAM capacity; it does not establish LED wiring.
The example below uses GPIO48 for the YD board. Verify the carrier/revision
before using it on a different processor board. This is a documentation example;
no NetworkMonitor firmware or enrolled configuration was changed for it.

Pin sources: [YD manufacturer](https://github.com/vcc-gnd/YD-ESP32-S3),
[Espressif revision details](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32s3/esp32-s3-devkitc-1/user_guide_v1.1.html#hardware-revision-details).

## ESP-IDF v6.1 example

Add `esp_driver_rmt` to the component's `REQUIRES`. Initialize once, then call
`nm_rgb_set(red, green, blue)` from a single owner task. Channels range from 0–255;
start around 16 for modest brightness. All zero turns it off.

```c
#include "driver/rmt_encoder.h"
#include "driver/rmt_tx.h"
#include "esp_check.h"
#include <stdint.h>

static rmt_channel_handle_t nm_rgb_channel;
static rmt_encoder_handle_t nm_rgb_encoder;
static rmt_symbol_word_t nm_rgb_symbols[25];

static void nm_rgb_init(void)
{
    rmt_tx_channel_config_t config = {
        .gpio_num = 48,
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10000000,
        .mem_block_symbols = 64,
        .trans_queue_depth = 1,
    };
    ESP_ERROR_CHECK(rmt_new_tx_channel(&config, &nm_rgb_channel));
    rmt_copy_encoder_config_t copy = {};
    ESP_ERROR_CHECK(rmt_new_copy_encoder(&copy, &nm_rgb_encoder));
    ESP_ERROR_CHECK(rmt_enable(nm_rgb_channel));
}

static void nm_rgb_set(uint8_t red, uint8_t green, uint8_t blue)
{
    uint32_t grb = ((uint32_t)green << 16) | ((uint32_t)red << 8) | blue;
    for (unsigned bit = 0; bit < 24; ++bit) {
        bool one = grb & (1u << (23 - bit));
        nm_rgb_symbols[bit] = (rmt_symbol_word_t){
            .level0 = 1, .duration0 = one ? 8 : 4,
            .level1 = 0, .duration1 = one ? 4 : 8,
        };
    }
    /* 100 microseconds low to latch the colour. */
    nm_rgb_symbols[24] = (rmt_symbol_word_t){.duration0 = 500, .duration1 = 500};
    rmt_transmit_config_t config = {.flags.queue_nonblocking = true};
    ESP_ERROR_CHECK(rmt_transmit(nm_rgb_channel, nm_rgb_encoder, nm_rgb_symbols,
                                 sizeof(nm_rgb_symbols), &config));
    ESP_ERROR_CHECK(rmt_tx_wait_all_done(nm_rgb_channel, 20));
}
```

Call `nm_rgb_init()` once, then use these values:

| Colour | `nm_rgb_set(red, green, blue)` |
| --- | --- |
| Red | `nm_rgb_set(16, 0, 0)` |
| Green | `nm_rgb_set(0, 16, 0)` |
| Blue | `nm_rgb_set(0, 0, 16)` |
| Yellow | `nm_rgb_set(16, 16, 0)` |
| Cyan | `nm_rgb_set(0, 16, 16)` |
| Purple | `nm_rgb_set(16, 0, 16)` |
| White | `nm_rgb_set(16, 16, 16)` |
| Amber | `nm_rgb_set(16, 3, 0)` |
| Off | `nm_rgb_set(0, 0, 0)` |

To blink, alternate a colour and off using task delays or a periodic state task.
RMT sends the waveform in hardware. Keep the LED task separate from microphone,
speaker and display work; do not send LED data or wait from an ISR.
