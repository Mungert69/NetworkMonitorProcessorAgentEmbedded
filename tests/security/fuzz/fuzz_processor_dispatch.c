/* Deterministic mutation smoke-fuzzer for the production dispatcher. Crypto and
 * delegated operations use the same recording adapters as test_processor_commands. */
#define main existing_dispatch_tests
#include "../../native/test_processor_commands.c"
#undef main

#include <stdint.h>

static uint32_t rng_state = UINT32_C(0x6d2b79f5);

static uint32_t next_random(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

int main(void)
{
    nm_esp_config config = {.auth_key = "test-key", .routing_id = "owned-route"};
    processor agent = {.config = &config, .poll_seconds = 60};
    static const char *const seeds[] = {
        "{}", "null", "[]", "{\"data\":null}",
        "{\"data\":{\"AuthKey\":\"test-key\"}}",
        "{\"data\":{\"AuthKey\":\"test-key\",\"Noise\":[1,true,null,{\"x\":\"y\"}]}}",
        "{\"data\":{\"AuthKey\":\"wrong\",\"Noise\":\"\\u0000\"}}",
        "{\"data\":{\"AuthKey\":\"test-key\",\"AuthKey\":\"wrong\"}}",
    };
    valid_signature = true;
    for (unsigned iteration = 0; iteration < 150000; ++iteration) {
        char body[4096];
        const char *seed = seeds[next_random() % (sizeof(seeds) / sizeof(seeds[0]))];
        size_t length = strlen(seed);
        memcpy(body, seed, length + 1);
        unsigned edits = next_random() % 12;
        while (edits-- && length) {
            size_t at = next_random() % length;
            switch (next_random() % 4) {
            case 0: body[at] ^= (char)(1u << (next_random() % 7)); break;
            case 1: body[at] = "{}[],:\\\"0123456789truefalsenull"[next_random() % 30]; break;
            case 2:
                if (length + 1 < sizeof(body)) {
                    memmove(body + at + 1, body + at, length - at + 1);
                    body[at] = (char)('a' + next_random() % 26);
                    ++length;
                }
                break;
            case 3:
                memmove(body + at, body + at + 1, length - at);
                --length;
                break;
            }
        }
        send(&agent, "owned-route",
             (next_random() & 1) ? "processorCommand" : "processorConnect", body);
    }
    puts("150000 mutated command-dispatch inputs completed");
    return 0;
}
