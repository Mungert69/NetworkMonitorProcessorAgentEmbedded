#include "ble_filter.h"
#include <assert.h>
#include <stdio.h>

int main(void)
{
    const uint8_t direct[] = {19,   0xff, 0xe1, 0x02, 0x01, 0xc6, 0x92, 0xa0, 0x3b, 0x9f,
                              0x81, 0xb7, 0x0b, 0,    0,    0,    0xc2, 0x0d, 0x7c, 0x1b};
    const uint8_t product[] = {22,   0xff, 0xe1, 0x02, 0x10, 0x02, 0x74, 0xa0,
                               0x01, 0xa3, 0x58, 0x4c, 0x6c, 0x29, 0xe6, 0x94,
                               0x5e, 0xe8, 0,    0x35, 0x3d, 0xf9, 0xfc};
    const uint8_t other[] = {19,   0xff, 0xe1, 0x02, 0x07, 0xc6, 0x92, 0xa0, 0x3b, 0x9f,
                             0x81, 0xb7, 0x0b, 0,    0,    0,    0xc2, 0x0d, 0x7c, 0x1b};
    nm_ble_advertisement item = {.address = "AA:BB:CC:DD:EE:FF"};
    nm_ble_filter filter = {.address = "AA:BB:CC:DD:EE:FF",
                            .company = 0x02e1,
                            .decoder = nm_ble_decoder_find("victron"),
                            .has_key = true,
                            .key_check = 0xa0};
    memcpy(item.data, direct, sizeof(direct));
    item.data_length = sizeof(direct);
    assert(nm_ble_advertisement_matches(&item, &filter));
    memcpy(item.data, product, sizeof(product));
    item.data_length = sizeof(product);
    filter.key_check = 0x4c;
    assert(nm_ble_advertisement_matches(&item, &filter));
    filter.key_check = 0xa0;
    assert(!nm_ble_advertisement_matches(&item, &filter));
    memcpy(item.data, other, sizeof(other));
    item.data_length = sizeof(other);
    assert(!nm_ble_advertisement_matches(&item, &filter));
    memcpy(item.data, direct, sizeof(direct));
    item.data_length = sizeof(direct);
    filter.address[0] = 'B';
    assert(!nm_ble_advertisement_matches(&item, &filter));
    filter.address[0] = 0; /* listen mode: any advertiser */
    assert(nm_ble_advertisement_matches(&item, &filter));
    item.data[0] = 255; /* malformed AD field length */
    assert(!nm_ble_advertisement_matches(&item, &filter));
    const uint8_t types[] = {1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 15};
    for (size_t i = 0; i < sizeof(types); i++) {
        memcpy(item.data, direct, sizeof(direct));
        item.data_length = sizeof(direct);
        item.data[4] = types[i];
        assert(nm_ble_advertisement_matches(&item, &filter));
    }
    filter.has_key = false;
    filter.key_check = 0xff;
    assert(nm_ble_advertisement_matches(&item, &filter));
    filter.decoder = nm_ble_decoder_find("bthome");
    filter.company = -1;
    const uint8_t service[] = {5, 0x16, 0xd2, 0xfc, 0x40, 0};
    memcpy(item.data, service, sizeof(service));
    item.data_length = sizeof(service);
    assert(nm_ble_advertisement_matches(&item, &filter));
    item.data[2] = 0xd3;
    assert(!nm_ble_advertisement_matches(&item, &filter));
    const uint8_t service32[] = {7, 0x20, 0xd2, 0xfc, 0, 0, 0x40, 0};
    memcpy(item.data, service32, sizeof(service32));
    item.data_length = sizeof(service32);
    assert(nm_ble_advertisement_matches(&item, &filter));
    const uint8_t service128[] = {19, 0x21, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0, 0,    0x80,
                                  0,  0x10, 0,    0,    0xd2, 0xfc, 0,    0, 0x40, 0};
    memcpy(item.data, service128, sizeof(service128));
    item.data_length = sizeof(service128);
    assert(nm_ble_advertisement_matches(&item, &filter));
    item.data[18] = 0x20;
    assert(!nm_ble_advertisement_matches(&item, &filter));
    filter.decoder = nm_ble_decoder_find("ruuvi");
    memset(item.data, 0, 28);
    item.data[0] = 27;
    item.data[1] = 255;
    item.data[2] = 0x99;
    item.data[3] = 4;
    item.data[4] = 5;
    item.data_length = 28;
    assert(nm_ble_advertisement_matches(&item, &filter));
    item.data[4] = 3;
    assert(!nm_ble_advertisement_matches(&item, &filter));
    puts("BLE advertisement filter tests passed");
    return 0;
}
