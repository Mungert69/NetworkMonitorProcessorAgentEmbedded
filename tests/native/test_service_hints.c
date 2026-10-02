#include "service_hints.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    assert(argc == 2);
    FILE *file = fopen(argv[1], "r");
    assert(file);
    /* Independent sequential reading supplies the expected mapping for every
     * port; production lookup uses byte-position binary search in embedded data. */
    char **expected = calloc(65536, sizeof(*expected));
    assert(expected);
    char line[256];
    unsigned count = 0, previous = 0;
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#')
            continue;
        unsigned port;
        char name[64], extra;
        assert(sscanf(line, "%u,%63[a-z0-9-]%c", &port, name, &extra) == 3 && extra == '\n');
        assert(port > previous && port <= 49151);
        previous = port;
        expected[port] = malloc(strlen(name) + 1);
        assert(expected[port]);
        strcpy(expected[port], name);
        ++count;
    }
    assert(!ferror(file) && count > 5000);
    fclose(file);
    for (unsigned port = 0; port <= 65535; ++port) {
        char result[64] = "unknown";
        bool found = nm_service_hint_lookup((uint16_t)port, result, sizeof(result));
        assert(found == (expected[port] != NULL));
        assert(!strcmp(result, found ? expected[port] : "unknown"));
        free(expected[port]);
    }
    free(expected);
    char small[3] = "xx";
    assert(!nm_service_hint_lookup(443, small, sizeof(small)) && !strcmp(small, "xx"));
    assert(!nm_service_hint_lookup(443, NULL, 64));
    puts("All 65,536 TCP ports checked against embedded service data");
    return 0;
}
