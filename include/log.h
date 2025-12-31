#ifndef LIGHTMAIL_LOG_H
#define LIGHTMAIL_LOG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Log levels */
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL
} log_level_t;

/* Initialize logger. If path == NULL use STDOUT. */
int log_init(const char *path);
void log_close(void);

/* Set runtime level for a service category (e.g., "imap", "pop3") */
void log_set_level(const char *service, log_level_t level);

/* Reload logging configuration from global config (non-allocating) */
int log_reload_config(void);

/* Emit a structured log. Hot path: no heap allocation. */
void log_emit(log_level_t level, const char *service, const char *user, const char *session, const char *fmt, ...) __attribute__((format(printf,5,6)));

/* Diagnostic: get number of dropped log entries */
unsigned int log_dropped_count(void);

/* Convenience macros to preserve existing LOGI/LOGE style */
#define LOG_INIT() log_init(NULL)
#define LOG_CLOSE() log_close()

#define LOGD(fmt, ...) log_emit(LOG_LEVEL_DEBUG, "main", NULL, NULL, (fmt), ##__VA_ARGS__)
#define LOGI(fmt, ...) log_emit(LOG_LEVEL_INFO,  "main", NULL, NULL, (fmt), ##__VA_ARGS__)
#define LOGW(fmt, ...) log_emit(LOG_LEVEL_WARN,  "main", NULL, NULL, (fmt), ##__VA_ARGS__)
#define LOGE(fmt, ...) log_emit(LOG_LEVEL_ERROR, "main", NULL, NULL, (fmt), ##__VA_ARGS__)

#define LOGF(fmt, ...) do { log_emit(LOG_LEVEL_CRITICAL, "main", NULL, NULL, (fmt), ##__VA_ARGS__); log_close(); _exit(1); } while(0)

/* Service-specific helpers */
#define LOGD_S(svc, fmt, ...) log_emit(LOG_LEVEL_DEBUG, (svc), NULL, NULL, (fmt), ##__VA_ARGS__)
#define LOGI_S(svc, fmt, ...) log_emit(LOG_LEVEL_INFO, (svc), NULL, NULL, (fmt), ##__VA_ARGS__)
#define LOGW_S(svc, fmt, ...) log_emit(LOG_LEVEL_WARN, (svc), NULL, NULL, (fmt), ##__VA_ARGS__)
#define LOGE_S(svc, fmt, ...) log_emit(LOG_LEVEL_ERROR, (svc), NULL, NULL, (fmt), ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
