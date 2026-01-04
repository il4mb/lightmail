#ifndef LIGHTMAIL_LOG_H
#define LIGHTMAIL_LOG_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/file.h>

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_CRITICAL = 4,
} log_level_t;

typedef struct {
    char path[256];
    char level[32];
    int min_level;
    int fd;  /* File descriptor for file locking */
} log_config_t;

/* Declaration - each process gets its own */
extern log_config_t log_config;

/* Function declarations */
int log_init();
void log_close(void);
void log_emit(log_level_t level, const char *fmt, ...);
void log_write(char *message);
log_level_t log_parse_level(const char *level_str);

/* Convenience macros */
#define LOGD(fmt, ...) log_emit(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) log_emit(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) log_emit(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) log_emit(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define LOGF(fmt, ...)                                    \
    do {                                                  \
        log_emit(LOG_LEVEL_CRITICAL, fmt, ##__VA_ARGS__); \
        log_close();                                      \
        _exit(1);                                         \
    } while (0)

#endif