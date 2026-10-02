#include "task.h"
int xTaskCreatePinnedToCoreWithCaps(void (*)(void *), const char *, unsigned, void *, unsigned,
                                  TaskHandle_t *, int, unsigned);
void vTaskDeleteWithCaps(TaskHandle_t);
