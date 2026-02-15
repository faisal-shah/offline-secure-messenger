#ifndef HAL_LOG_H
#define HAL_LOG_H

/* Log a timestamped debug message.
 * context: short label (e.g., "Transport", "Outbox")
 * msg: descriptive text (may be truncated on constrained platforms) */
void hal_log(const char *context, const char *msg);

#endif /* HAL_LOG_H */
