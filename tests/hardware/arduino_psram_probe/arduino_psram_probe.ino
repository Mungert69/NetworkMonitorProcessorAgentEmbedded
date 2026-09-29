#include <Arduino.h>
#include <esp_heap_caps.h>

void setup() {
  Serial.begin(115200);
  delay(1000);
  const size_t bytes = 7u * 1024u * 1024u;
  Serial.printf("ARDUINO_PSRAM_PROBE SDK=%s size=%u free=%u\n", ESP.getSdkVersion(),
                (unsigned)ESP.getPsramSize(), (unsigned)ESP.getFreePsram());

  volatile uint32_t *buffer = static_cast<volatile uint32_t *>(
      heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
  if (buffer == nullptr) {
    Serial.println("ARDUINO_PSRAM_PROBE_ALLOC_FAILED");
    return;
  }
  for (size_t i = 0; i < bytes / sizeof(*buffer); ++i)
    buffer[i] = static_cast<uint32_t>(i) ^ (static_cast<uint32_t>(i) >> 16) ^ 0xa5a55a5au;
  for (size_t i = 0; i < bytes / sizeof(*buffer); ++i) {
    uint32_t expected = static_cast<uint32_t>(i) ^ (static_cast<uint32_t>(i) >> 16) ^ 0xa5a55a5au;
    if (buffer[i] != expected) {
      Serial.printf("ARDUINO_PSRAM_PROBE_MISMATCH index=%u\n", (unsigned)i);
      free(const_cast<uint32_t *>(buffer));
      return;
    }
  }
  free(const_cast<uint32_t *>(buffer));
  Serial.printf("ARDUINO_PSRAM_PROBE_PASS checked_bytes=%u\n", (unsigned)bytes);
}

void loop() { delay(1000); }
