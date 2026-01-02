#ifndef LIGHTMAIL_LOG_H
#define LIGHTMAIL_LOG_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_CRITICAL = 4,
} log_level_t;

/* Log output destinations */
typedef enum {
    LOG_OUTPUT_FILE = 0,
    LOG_OUTPUT_JOURNAL = 1,
    LOG_OUTPUT_BOTH = 2,
    LOG_OUTPUT_STDOUT = 3,
} log_output_t;

/* Initialize logging system
 * path: file path for file-based logging (NULL for stdout only)
 * output: output destination (file, journal, both, or stdout)
 * Returns: 0 on success, -1 on error
 */
int log_init(const char *path, log_output_t output);

/* Close logging system and flush all pending messages */
void log_close(void);

/* Reload configuration */
int log_reload_config(void);

/* Set log level for a specific service */
void log_set_level(const char *service, log_level_t level);

/* Emit a log message */
void log_emit(log_level_t level, const char *fmt, ...);

/* Get dropped message count (for diagnostics) */
unsigned int log_dropped_count(void);

/* Convenience macros */
#define LOG_INIT() log_init(NULL, LOG_OUTPUT_STDOUT)
#define LOG_INIT_FILE(path) log_init(path, LOG_OUTPUT_FILE)
#define LOG_INIT_JOURNAL() log_init(NULL, LOG_OUTPUT_JOURNAL)
#define LOG_INIT_BOTH(path) log_init(path, LOG_OUTPUT_BOTH)
#define LOG_CLOSE() log_close()

/* Log level macros for compatibility */
#define LOGD(fmt, ...) log_emit(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) log_emit(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) log_emit(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) log_emit(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define LOGF(fmt, ...) do { log_emit(LOG_LEVEL_CRITICAL, fmt, ##__VA_ARGS__); log_close(); _exit(1); } while(0)

#endif
