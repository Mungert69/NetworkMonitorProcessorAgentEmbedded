#include <assert.h>
#include <brotli/encode.h>
#include <brotli/decode.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t calls, fail_at, live;
static void *allocate(void *unused, size_t size)
{
    (void)unused;
    if (++calls == fail_at)
        return NULL;
    void *p = malloc(size);
    if (p)
        ++live;
    return p;
}
static void release(void *unused, void *p)
{
    (void)unused;
    if (p) {
        assert(live);
        --live;
        free(p);
    }
}
static void allocation_failures(void)
{
    uint8_t input[4096], output[8192];
    memset(input, 'a', sizeof(input));
    size_t total_calls = 0;
    for (size_t failure = 0; failure <= total_calls; ++failure) {
        calls = live = 0;
        fail_at = failure;
        BrotliEncoderState *s = BrotliEncoderCreateInstance(allocate, release, NULL);
        if (s) {
            assert(BrotliEncoderSetParameter(s, BROTLI_PARAM_QUALITY, 0));
            size_t in = sizeof(input), out = sizeof(output);
            const uint8_t *next_in = input;
            uint8_t *next_out = output;
            int ok = BrotliEncoderCompressStream(s, BROTLI_OPERATION_FINISH, &in, &next_in, &out,
                                                 &next_out, NULL);
            if (failure == 0)
                assert(ok && BrotliEncoderIsFinished(s));
            else
                assert(!ok);
            BrotliEncoderDestroyInstance(s);
        } else
            assert(failure != 0);
        if (failure == 0)
            total_calls = calls;
        assert(live == 0);
    }
}
int main(int argc, char **argv)
{
    const size_t sizes[] = {0,     1,      2,      3,      15,     16,     17,     255,   256,
                            257,   1023,   1024,   1025,   4095,   4096,   4097,   65535, 65536,
                            65537, 131071, 131072, 131073, 262143, 262144, 262145, 524288};
    const char pattern[] =
        "{\"ID\":18446744073709551615,\"Message\":\"monitor test\",\"IsUp\":true}";
    for (unsigned kind = 0; kind < 3; ++kind) {
        for (size_t c = 0; c < sizeof(sizes) / sizeof(sizes[0]); ++c) {
            size_t length = sizes[c], capacity = BrotliEncoderMaxCompressedSize(length);
            uint8_t *input = malloc(length + 1), *output = malloc(capacity + 16);
            uint8_t *decoded = malloc(length + 1);
            assert(input && output && decoded);
            uint32_t random = 12345;
            for (size_t i = 0; i < length; ++i) {
                random ^= random << 13;
                random ^= random >> 17;
                random ^= random << 5;
                input[i] = kind == 0   ? (uint8_t)pattern[i % (sizeof(pattern) - 1)]
                           : kind == 1 ? (uint8_t)random
                                       : 'a';
            }
            memset(output, 0xa5, capacity + 16);
            size_t encoded = capacity;
            assert(BrotliEncoderCompress(0, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_TEXT, length, input,
                                         &encoded, output));
            assert(encoded <= capacity);
            for (size_t i = capacity; i < capacity + 16; ++i)
                assert(output[i] == 0xa5);
            size_t restored = length + 1;
            assert(BrotliDecoderDecompress(encoded, output, &restored, decoded) ==
                   BROTLI_DECODER_RESULT_SUCCESS);
            assert(restored == length && !memcmp(input, decoded, length));
            if (argc == 2) {
                char path[4096];
                int n = snprintf(path, sizeof(path), "%s/%u-%zu.br", argv[1], kind, length);
                assert(n > 0 && (size_t)n < sizeof(path));
                FILE *f = fopen(path, "wb");
                assert(f);
                assert(fwrite(output, 1, encoded, f) == encoded);
                assert(fclose(f) == 0);
                n = snprintf(path, sizeof(path), "%s/%u-%zu.raw", argv[1], kind, length);
                assert(n > 0 && (size_t)n < sizeof(path));
                f = fopen(path, "wb");
                assert(f);
                assert(fwrite(input, 1, length, f) == length);
                assert(fclose(f) == 0);
            }
            size_t tiny = 0;
            assert(!BrotliEncoderCompress(0, 22, BROTLI_MODE_TEXT, length, input, &tiny, output));
            if (length > 1) {
                tiny = 1;
                memset(output, 0xa5, capacity + 16);
                assert(
                    !BrotliEncoderCompress(0, 22, BROTLI_MODE_TEXT, length, input, &tiny, output));
                for (size_t i = 1; i < capacity + 16; ++i)
                    assert(output[i] == 0xa5);
            }
#ifdef NM_Q0_ONLY
            for (int quality = 1; quality <= 11; ++quality) {
                encoded = capacity;
                assert(!BrotliEncoderCompress(quality, 22, BROTLI_MODE_TEXT, length, input,
                                              &encoded, output));
            }
#endif
            free(decoded);
            free(output);
            free(input);
        }
    }
#ifdef NM_Q0_ONLY
    BrotliEncoderState *s = BrotliEncoderCreateInstance(NULL, NULL, NULL);
    assert(s);
    assert(!BrotliEncoderSetParameter(s, BROTLI_PARAM_QUALITY, 1));
    assert(BrotliEncoderSetParameter(s, BROTLI_PARAM_QUALITY, 0));
    BrotliEncoderDestroyInstance(s);
#endif
    allocation_failures();
    puts("78 boundary/data cases and allocation failure checks passed");
    return 0;
}
