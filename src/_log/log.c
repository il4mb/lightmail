#include "log.h"
#include <lightmail.h>

/* Each process has its own instance */
log_config_t log_config;

log_level_t log_parse_level(const char *level_str) {
    if (!level_str || strcmp(level_str, "*") == 0)
        return LOG_LEVEL_DEBUG;
    if (strcmp(level_str, "debug") == 0)
        return LOG_LEVEL_DEBUG;
    if (strcmp(level_str, "info") == 0)
        return LOG_LEVEL_INFO;
    if (strcmp(level_str, "warn") == 0)
        return LOG_LEVEL_WARN;
    if (strcmp(level_str, "error") == 0)
        return LOG_LEVEL_ERROR;
    if (strcmp(level_str, "critical") == 0)
        return LOG_LEVEL_CRITICAL;
    return LOG_LEVEL_INFO; /* default */
}

int log_init() {
    /* Initialize config for this process */
    memset(&log_config, 0, sizeof(log_config_t));
    log_config.fd = -1;

    /* Get configuration from config file */
    const char *clogf = get_config_value("logging", "path");
    const char *cloglevel = get_config_value("logging", "level");

    /* Set log path */
    if (clogf && clogf[0] != '\0') {
        strncpy(log_config.path, clogf, sizeof(log_config.path) - 1);

        /* Try to open the log file for appending */
        FILE *test_fp = fopen(log_config.path, "a");
        if (test_fp) {
            fclose(test_fp);
        } else {
            /* Can't open log file, clear the path */
            log_config.path[0] = '\0';
        }
    }

    /* Set log level */
    if (cloglevel && cloglevel[0] != '\0') {
        strncpy(log_config.level, cloglevel, sizeof(log_config.level) - 1);
    } else {
        strcpy(log_config.level, "*");
    }

    /* Parse minimum log level */
    log_config.min_level = log_parse_level(log_config.level);

    return 0;
}

void log_close(void) {
    /* Close file descriptor if open */
    if (log_config.fd != -1) {
        close(log_config.fd);
        log_config.fd = -1;
    }
}

void log_emit(log_level_t level, const char *fmt, ...) {
    /* Check if this message should be logged based on level */
    if (level < log_config.min_level) {
        return;
    }

    char level_str[16];
    switch (level) {
    case LOG_LEVEL_DEBUG:
        strcpy(level_str, "DEBUG");
        break;
    case LOG_LEVEL_INFO:
        strcpy(level_str, "INFO");
        break;
    case LOG_LEVEL_WARN:
        strcpy(level_str, "WARN");
        break;
    case LOG_LEVEL_ERROR:
        strcpy(level_str, "ERROR");
        break;
    case LOG_LEVEL_CRITICAL:
        strcpy(level_str, "CRITICAL");
        break;
    default:
        strcpy(level_str, "UNKNOWN");
        break;
    }

    /* Get current time */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    /* Get process ID */
    pid_t pid = getpid();

    /* Format the message */
    char message[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    /* Prepare the final log line */
    char log_line[1200];
    int len = snprintf(log_line, sizeof(log_line), "[%s] [PID:%d] [%s] %s\n", time_str, pid, level_str, message);

    if (len > 0) {
        log_write(log_line);
    }
}

void log_write(char *message) {
    if (log_config.path[0] != '\0') {
        FILE *fp = fopen(log_config.path, "a");
        if (fp) {
            flockfile(fp);
            fputs(message, fp);
            fflush(fp);
            funlockfile(fp);
            fclose(fp);
        }
    }
}