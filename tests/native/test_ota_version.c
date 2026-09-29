#include "ota_version.h"
#include <assert.h>
#include <stdio.h>

int main(void)
{
    unsigned a[3], b[3];
    const char *invalid[] = {NULL, "", "1", "1.2", "1.2.3.4", "01.2.3",
        "1.02.3", "-1.2.3", "1.2.3-rc1", "1.2.3 ", "4294967296.0.0",
        "999999999999999999999999999999999999999.0.0"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        assert(!parse_version(invalid[i], a));
    assert(parse_version("0.1.9", a));
    assert(parse_version("0.1.10", b));
    assert(compare_version(a, b) < 0);
    assert(compare_version(b, a) > 0);
    assert(compare_version(a, a) == 0);
    assert(parse_version("1.0.0", a));
    assert(compare_version(a, b) > 0);
    assert(ota_version_permitted("0.1.10", "0.1.9"));
    assert(ota_version_permitted("0.1.9", "0.1.10"));
    assert(!ota_version_permitted("0.1.9", "0.1.9"));
    assert(!ota_version_permitted("01.1.9", "0.1.10"));
    assert(!ota_version_permitted("0.1.9", "invalid"));
    puts("OTA version policy tests passed");
    return 0;
}
