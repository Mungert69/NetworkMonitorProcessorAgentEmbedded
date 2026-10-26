#ifndef NM_TEST_PING_STORAGE_MEMORY_H
#define NM_TEST_PING_STORAGE_MEMORY_H
#include "ping_storage.h"
extern nm_ping_storage_mode nm_test_ping_mode;
extern nm_ping_storage_capacity nm_test_ping_capacity;
extern bool nm_test_ping_fail_read, nm_test_ping_fail_write, nm_test_ping_fail_delete;
extern unsigned nm_test_ping_writes, nm_test_ping_deletes;
void nm_test_ping_reset(void);
#endif
