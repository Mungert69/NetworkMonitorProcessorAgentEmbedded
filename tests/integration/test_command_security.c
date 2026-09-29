#include "command_security.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *directory, const char *name)
{
#ifdef ESP_PLATFORM
    (void)directory;
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); ++i) {
        if (!strcmp(name, fixtures[i].name)) {
            char *copy = malloc(fixtures[i].length + 1);
            assert(copy);
            memcpy(copy, fixtures[i].bytes, fixtures[i].length);
            copy[fixtures[i].length] = 0;
            return copy;
        }
    }
    assert(!"Missing embedded fixture");
    return NULL;
#else
    char path[2048];
    int n = snprintf(path, sizeof(path), "%s/%s", directory, name);
    assert(n > 0 && (size_t)n < sizeof(path));
    FILE *file = fopen(path, "rb");
    assert(file && fseek(file, 0, SEEK_END) == 0);
    long length = ftell(file);
    assert(length >= 0 && length <= 500000 && fseek(file, 0, SEEK_SET) == 0);
    char *buffer = calloc((size_t)length + 1, 1);
    assert(buffer && fread(buffer, 1, (size_t)length, file) == (size_t)length);
    fclose(file);
    return buffer;
#endif
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    char *key = read_file(argv[1], "public.pem");
    char *target = read_file(argv[1], "target.txt");
    char *policy = read_file(argv[1], "policy.txt");
    unsigned count = 0;
    for (char *operation = strtok(policy, "\r\n"); operation; operation = strtok(NULL, "\r\n")) {
        assert(nm_command_requires_signature(operation));
        char name[128];
        assert(snprintf(name, sizeof(name), "%s.json", operation) > 0);
        char *json = read_file(argv[1], name);
        yyjson_mut_doc *doc = nm_json_read(json, strlen(json));
        yyjson_mut_val *envelope = yyjson_mut_doc_get_root(doc);
        assert(envelope);
        yyjson_mut_doc *verified = nm_command_verify(envelope, operation, target, (unsigned char *)key, strlen(key) + 1);
        assert(yyjson_mut_is_obj(yyjson_mut_doc_get_root(verified)));
        yyjson_mut_doc_free(verified);
        assert(!nm_command_verify(envelope, "wrong-operation", target, (unsigned char *)key, strlen(key) + 1));
        assert(!nm_command_verify(envelope, operation, "wrong-device", (unsigned char *)key, strlen(key) + 1));
        assert(!nm_command_verify(envelope, operation, target, (unsigned char *)"invalid", 8));
        char *signature = (char *)yyjson_mut_get_str(yyjson_mut_obj_get(envelope, "Signature"));
        char saved = signature[0]; signature[0] = saved == 'A' ? 'B' : 'A';
        assert(!nm_command_verify(envelope, operation, target, (unsigned char *)key, strlen(key) + 1));
        signature[0] = saved;
        char *payload = (char *)yyjson_mut_get_str(yyjson_mut_obj_get(envelope, "Payload"));
        saved = payload[0]; payload[0] = saved == 'A' ? 'B' : 'A';
        assert(!nm_command_verify(envelope, operation, target, (unsigned char *)key, strlen(key) + 1));
        payload[0] = saved;
        yyjson_mut_set_uint(yyjson_mut_obj_get(envelope, "Version"), 2);
        assert(!nm_command_verify(envelope, operation, target, (unsigned char *)key, strlen(key) + 1));
        yyjson_mut_set_uint(yyjson_mut_obj_get(envelope, "Version"), 1);
        yyjson_mut_set_real(yyjson_mut_obj_get(envelope, "Version"), 1.0);
        assert(!nm_command_verify(envelope, operation, target, (unsigned char *)key, strlen(key) + 1));
        yyjson_mut_set_uint(yyjson_mut_obj_get(envelope, "Version"), 1);
        yyjson_mut_set_str(yyjson_mut_obj_get(envelope, "Algorithm"), "none");
        assert(!nm_command_verify(envelope, operation, target, (unsigned char *)key, strlen(key) + 1));
        yyjson_mut_set_str(yyjson_mut_obj_get(envelope, "Algorithm"), "ES256");
        yyjson_mut_obj_add_uint(doc, envelope, "Version", 1);
        assert(!nm_command_verify(envelope, operation, target, (unsigned char *)key, strlen(key) + 1));
        yyjson_mut_doc_free(doc);
        free(json);
        ++count;
#ifdef ESP_PLATFORM
        printf("Verified signed operation %u: %s\n", count, operation);
        vTaskDelay(1);
#endif
    }
    assert(count == 17);
    char *large_json = read_file(argv[1], "large-processorInit.json");
    yyjson_mut_doc *large_doc = nm_json_read(large_json, strlen(large_json));
    yyjson_mut_val *large_envelope = yyjson_mut_doc_get_root(large_doc);
    yyjson_mut_doc *large_verified = nm_command_verify(large_envelope, "processorInit", target,
        (unsigned char *)key, strlen(key) + 1);
    assert(yyjson_mut_is_obj(yyjson_mut_doc_get_root(large_verified)));
    yyjson_mut_doc_free(large_verified);
    yyjson_mut_doc_free(large_doc);
    free(large_json);
    const char *malformed[] = {"invalid-truncated.json", "invalid-trailing.json",
        "invalid-oversized-field.json", "invalid-empty.json"};
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
        char *json = read_file(argv[1], malformed[i]);
        yyjson_mut_doc *doc = nm_json_read(json, strlen(json));
        yyjson_mut_val *envelope = yyjson_mut_doc_get_root(doc);
        assert(envelope && !nm_command_verify(envelope, "processorInit", target,
            (unsigned char *)key, strlen(key) + 1));
        yyjson_mut_doc_free(doc);
        free(json);
    }
    const char *unsigned_operations[] = {"processorConnect", "processorWakeUp", "removePingInfos",
        "processorAlertFlag", "processorAlertSent", "processorResetAlerts", "processorUserEvent"};
    for (size_t i = 0; i < sizeof(unsigned_operations) / sizeof(unsigned_operations[0]); ++i)
        assert(!nm_command_requires_signature(unsigned_operations[i]));
    const char *plain_json="{\"AuthKey\":\"test-only\"}";
    yyjson_mut_doc *plain_doc=nm_json_read(plain_json,strlen(plain_json));
    yyjson_mut_val *plain=yyjson_mut_doc_get_root(plain_doc);
    assert(!nm_command_verify(plain, "processorInit", target, (unsigned char *)key, strlen(key) + 1));
    yyjson_mut_doc_free(plain_doc);
    free(policy); free(target); free(key);
    puts("C verifier: all 17 .NET-generated operation fixtures verified; tampering, wrong targets, unsigned and downgrade cases rejected");
    return 0;
}
