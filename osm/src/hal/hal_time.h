#ifndef HAL_TIME_H
#define HAL_TIME_H

#include <stdint.h>

/* Get monotonic time in milliseconds (for LVGL tick and delays) */
uint32_t hal_get_ms(void);

/* Delay for the specified number of milliseconds */
void hal_delay_ms(uint32_t ms);

#endif /* HAL_TIME_H */
