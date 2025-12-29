#ifndef LOG_H
#define LOG_H
#include <syslog.h>

#define LOG_INIT() \
    openlog("lightmail", LOG_PID | LOG_NDELAY, LOG_MAIL)

#define LOG_CLOSE() \
    closelog()

// Debug level
#define LOGD(fmt, ...) syslog(LOG_DEBUG, fmt, ##__VA_ARGS__)
// Info level
#define LOGI(fmt, ...) syslog(LOG_INFO, fmt, ##__VA_ARGS__)
// Warning level
#define LOGW(fmt, ...) syslog(LOG_WARNING, fmt, ##__VA_ARGS__)
// Error level
#define LOGE(fmt, ...) syslog(LOG_ERR, fmt, ##__VA_ARGS__)
// Fatal level - logs the message and exits
#define LOGF(fmt, ...)                        \
    do {                                      \
        syslog(LOG_CRIT, fmt, ##__VA_ARGS__); \
        closelog();                           \
        _exit(1);                             \
    } while (0)
#endif