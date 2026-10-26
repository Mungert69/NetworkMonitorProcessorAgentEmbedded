#include <stdint.h>
#include <time.h>
/* Native boundary adapter; zero selects the actual host clock. */
int64_t nm_test_recording_utc;
time_t nm_network_recording_time(void)
{
    return nm_test_recording_utc ? (time_t)nm_test_recording_utc : time(NULL);
}
