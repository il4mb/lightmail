#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <lightmail.h>
#include <limits.h>
#include <log.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>
#endif

static char current_path[PATH_MAX] = "";

static log_level_t parse_level(const char *s) {
    if (!s)
        return LOG_LEVEL_INFO;
    if (strcasecmp(s, "DEBUG") == 0)
        return LOG_LEVEL_DEBUG;
    if (strcasecmp(s, "INFO") == 0)
        return LOG_LEVEL_INFO;
    if (strcasecmp(s, "WARN") == 0)
        return LOG_LEVEL_WARN;
    if (strcasecmp(s, "ERROR") == 0)
        return LOG_LEVEL_ERROR;
    if (strcasecmp(s, "CRITICAL") == 0)
        return LOG_LEVEL_CRITICAL;
    return LOG_LEVEL_INFO;
}

/* forward declaration - implementation is after static variables */
int log_reload_config(void);

#define RING_ORDER 10
#define RING_SIZE (1u << RING_ORDER)
#define RING_MASK (RING_SIZE - 1u)
#define SERVICE_NAME_LEN 16
#define USER_LEN 64
#define SESSION_LEN 64
#define MSG_LEN 512

struct log_entry {
    uint64_t ts_ns;
    log_level_t level;
    char msg[MSG_LEN];
};

static struct log_entry ring[RING_SIZE];
static atomic_uint head = 0;
static atomic_uint tail = 0;
static pthread_t flusher_thread;
static pthread_mutex_t flusher_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t flusher_cond = PTHREAD_COND_INITIALIZER;
static int out_fd = STDOUT_FILENO;
static atomic_int running = 0;
static atomic_uint dropped = 0;

/* Used to temporarily pause flusher when performing destructive operations like 'clear on reload' */
static atomic_int flusher_paused = 0;
static atomic_int flusher_paused_ack = 0;

/* Output destination configuration */
static atomic_int output_mode = LOG_OUTPUT_STDOUT;
static atomic_int journal_enabled = 0;

/* Track if we're running as a daemon */
static atomic_int daemon_mode = 0;

/* simple service level mapping */
struct svc_level {
    char name[SERVICE_NAME_LEN];
    log_level_t level;
};
static struct svc_level svc_levels[32];
static int svc_levels_count = 0;
static pthread_mutex_t svc_lock = PTHREAD_MUTEX_INITIALIZER;
static log_level_t default_level = LOG_LEVEL_INFO;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static const char *level_to_str(log_level_t l) {
    switch (l) {
    case LOG_LEVEL_DEBUG:
        return "DEBUG";
    case LOG_LEVEL_INFO:
        return "INFO";
    case LOG_LEVEL_WARN:
        return "WARN";
    case LOG_LEVEL_ERROR:
        return "ERROR";
    case LOG_LEVEL_CRITICAL:
        return "CRITICAL";
    default:
        return "UNKNOWN";
    }
}

/* Get systemd priority level (0-7) - defined when systemd support is enabled */

/* Send log to systemd journal */
static void journal_send(struct log_entry *e) {
#ifdef HAVE_SYSTEMD
    if (!atomic_load(&journal_enabled))
        return;

    /* Map log levels to systemd/syslog priorities */
    static int get_systemd_priority(log_level_t l) {
        switch (l) {
        case LOG_LEVEL_DEBUG:
            return LOG_DEBUG;
        case LOG_LEVEL_INFO:
            return LOG_INFO;
        case LOG_LEVEL_WARN:
            return LOG_WARNING;
        case LOG_LEVEL_ERROR:
            return LOG_ERR;
        case LOG_LEVEL_CRITICAL:
            return LOG_CRIT;
        default:
            return LOG_INFO;
        }
    }

    int priority = get_systemd_priority(e->level);

    sd_journal_send(
        "PRIORITY=%d", priority,
        "SYSLOG_IDENTIFIER=lightmail",
        "MESSAGE=%s", e->msg,
        NULL);
#else
    (void)e;
#endif
}

/* Write log entry to file descriptor */
static ssize_t write_log_entry(int fd, struct log_entry *e) {
    if (fd < 0)
        return -1;

    char buf[1024];
    /* Use ISO 8601 timestamp format for human readability */
    time_t sec = e->ts_ns / 1000000000ULL;
    long nsec = e->ts_ns % 1000000000ULL;

    struct tm *tm_info = localtime(&sec);
    char ts_str[64];
    strftime(ts_str, sizeof(ts_str), "%Y-%m-%dT%H:%M:%S", tm_info);

    int n = snprintf(buf, sizeof(buf), "%s.%09ldZ [%s] %s\n", ts_str, nsec, level_to_str(e->level), e->msg);

    if (n > 0) {
        return write(fd, buf, (size_t)n);
    }
    return -1;
}

static void flusher_run(void) {
    while (atomic_load(&running)) {
        /* respect pause request for destructive operations */
        pthread_mutex_lock(&flusher_lock);
        if (atomic_load(&flusher_paused)) {
            /* indicate we're paused and notify waiter */
            atomic_store(&flusher_paused_ack, 1);
            pthread_cond_signal(&flusher_cond);
            while (atomic_load(&flusher_paused)) {
                pthread_cond_wait(&flusher_cond, &flusher_lock);
            }
            atomic_store(&flusher_paused_ack, 0);
        }
        pthread_mutex_unlock(&flusher_lock);

        unsigned int t = atomic_load(&tail);
        unsigned int h = atomic_load(&head);
        if (t == h) {
            /* nothing to flush - wait */
            pthread_mutex_lock(&flusher_lock);
            pthread_cond_wait(&flusher_cond, &flusher_lock);
            pthread_mutex_unlock(&flusher_lock);
            continue;
        }

        /* drain until head */
        while ((t = atomic_load(&tail)) != (h = atomic_load(&head))) {
            struct log_entry *e = &ring[t & RING_MASK];
            log_output_t mode = atomic_load(&output_mode);

            /* Write to file if enabled */
            if (mode != LOG_OUTPUT_JOURNAL && out_fd != STDOUT_FILENO) {
                ssize_t r = write_log_entry(out_fd, e);
                (void)r;
            }

            /* Write to stdout ONLY if explicitly in STDOUT mode */
            if (mode == LOG_OUTPUT_STDOUT) {
                ssize_t r = write_log_entry(STDOUT_FILENO, e);
                (void)r;
            }

            /* Send to systemd journal if enabled */
            if (mode == LOG_OUTPUT_JOURNAL || mode == LOG_OUTPUT_BOTH) {
                journal_send(e);
            }

            atomic_store(&tail, t + 1);
        }
    }

    /* drain remaining entries on shutdown */
    unsigned int t = atomic_load(&tail);
    unsigned int h = atomic_load(&head);
    while (t != h) {
        struct log_entry *e = &ring[t & RING_MASK];
        log_output_t mode = atomic_load(&output_mode);

        if (mode != LOG_OUTPUT_JOURNAL && out_fd != STDOUT_FILENO) {
            ssize_t r = write_log_entry(out_fd, e);
            (void)r;
        }

        if ((mode == LOG_OUTPUT_STDOUT || mode == LOG_OUTPUT_FILE) &&
            !atomic_load(&daemon_mode)) {
            ssize_t r = write_log_entry(STDOUT_FILENO, e);
            (void)r;
        }

        if (mode == LOG_OUTPUT_JOURNAL || mode == LOG_OUTPUT_BOTH) {
            journal_send(e);
        }

        t++;
    }
}

static void *flusher_thread_main(void *arg) {
    (void)arg;
    flusher_run();
    return NULL;
}

/* Ensure log directory exists with proper permissions */
static int ensure_log_dir(const char *path) {
    char dir_path[PATH_MAX];
    strncpy(dir_path, path, sizeof(dir_path) - 1);
    dir_path[sizeof(dir_path) - 1] = '\0';

    /* Find the last slash to get directory portion */
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash && last_slash != dir_path) {
        *last_slash = '\0'; /* Truncate to get directory */

        /* Create directory if it doesn't exist */
        if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
            return -1;
        }
    }
    return 0;
}

int log_init(const char *path, log_output_t output) {
    if (atomic_load(&running))
        return 0; /* already started */

    /* Determine output mode from config if not explicitly set */
    if (output == LOG_OUTPUT_STDOUT) {
        const char *output_str = get_config_value("logging", "output");
        if (output_str) {
            if (strcasecmp(output_str, "journal") == 0) {
                output = LOG_OUTPUT_JOURNAL;
            } else if (strcasecmp(output_str, "both") == 0) {
                output = LOG_OUTPUT_BOTH;
            } else if (strcasecmp(output_str, "file") == 0) {
                output = LOG_OUTPUT_FILE;
            } else if (strcasecmp(output_str, "stdout") == 0) {
                output = LOG_OUTPUT_STDOUT;
            } else {
                /* Default to FILE for any other value */
                output = LOG_OUTPUT_FILE;
            }
        } else {
            /* No config specified - DEFAULT TO FILE */
            output = LOG_OUTPUT_FILE;
        }
    }

    atomic_store(&output_mode, output);

    /* Setup file descriptor based on output mode */
    if (output != LOG_OUTPUT_JOURNAL) {
        if (path) {
            /* Ensure parent directory exists */
            if (ensure_log_dir(path) != 0) {
                return -1;
            }

            int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd < 0)
                return -1;
            out_fd = fd;
        } else {
            /* If no path provided but output is FILE, use default path */
            if (output == LOG_OUTPUT_FILE) {
                const char *default_path = "/var/log/lightmail/lightmail.log";
                if (ensure_log_dir(default_path) != 0) {
                    /* Fallback to /tmp if /var/log not accessible */
                    default_path = "/tmp/lightmail.log";
                }

                int fd = open(default_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
                if (fd >= 0) {
                    out_fd = fd;
                } else {
                    /* Last resort: use stdout */
                    out_fd = STDOUT_FILENO;
                }
            } else {
                out_fd = STDOUT_FILENO;
            }
        }
    }

    /* Check if systemd journal is available */
#ifdef HAVE_SYSTEMD
    if (output == LOG_OUTPUT_JOURNAL || output == LOG_OUTPUT_BOTH) {
        atomic_store(&journal_enabled, 1);
    }
#else
    if (output == LOG_OUTPUT_JOURNAL) {
        /* Fall back to file if journal requested but not available */
        if (path) {
            int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd >= 0) {
                out_fd = fd;
            } else {
                out_fd = STDOUT_FILENO;
            }
        }
        atomic_store(&output_mode, LOG_OUTPUT_FILE);
    }
#endif

    atomic_store(&running, 1);
    atomic_store(&head, 0);
    atomic_store(&tail, 0);
    pthread_create(&flusher_thread, NULL, flusher_thread_main, NULL);

    /* Write a divider to the log file to indicate a new session */
    if (out_fd != STDOUT_FILENO && out_fd >= 0) {
        write(out_fd, "\n--- LightMail Log Session Started ---\n\n", 40);
    }

    return 0;
}

/* Initialize logging for daemon mode */
int log_init_daemon(const char *path, log_output_t output) {
    atomic_store(&daemon_mode, 1);
    return log_init(path, output);
}

void log_close(void) {
    if (!atomic_load(&running))
        return;
    atomic_store(&running, 0);
    pthread_mutex_lock(&flusher_lock);
    pthread_cond_signal(&flusher_cond);
    pthread_mutex_unlock(&flusher_lock);
    pthread_join(flusher_thread, NULL);

    if (out_fd != STDOUT_FILENO && out_fd >= 0) {
        /* Sync file to disk before closing */
        fsync(out_fd);
        close(out_fd);
        out_fd = STDOUT_FILENO;
    }

    atomic_store(&journal_enabled, 0);
    atomic_store(&daemon_mode, 0);
}

/* Reopen log file - useful after daemonizing when stdio is redirected */
int log_reopen(const char *path) {
    if (!atomic_load(&running))
        return -1;

    if (path) {
        /* Ensure parent directory exists */
        if (ensure_log_dir(path) != 0) {
            return -1;
        }

        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0)
            return -1;

        /* Pause flusher during file descriptor swap */
        atomic_store(&flusher_paused, 1);
        pthread_mutex_lock(&flusher_lock);
        while (!atomic_load(&flusher_paused_ack)) {
            pthread_cond_wait(&flusher_cond, &flusher_lock);
        }

        /* Close old file descriptor */
        if (out_fd != STDOUT_FILENO && out_fd >= 0) {
            fsync(out_fd);
            close(out_fd);
        }

        /* Set new file descriptor */
        out_fd = fd;
        strncpy(current_path, path, sizeof(current_path) - 1);
        current_path[sizeof(current_path) - 1] = '\0';

        /* Resume flusher */
        atomic_store(&flusher_paused, 0);
        pthread_cond_broadcast(&flusher_cond);
        pthread_mutex_unlock(&flusher_lock);
    }

    return 0;
}

int log_reload_config(void) {
    const char *path = get_config_value("logging", "path");
    const char *level = get_config_value("logging", "level");
    const char *output = get_config_value("logging", "output");

    /* Reopen path if changed */
    if (path && (current_path[0] == '\0' || strcmp(current_path, path) != 0)) {
        log_reopen(path);
    }

    /* Apply default level */
    if (level) {
        default_level = parse_level(level);
    }

    /* Apply output mode changes */
    if (output) {
        log_output_t new_output;
        if (strcasecmp(output, "journal") == 0) {
            new_output = LOG_OUTPUT_JOURNAL;
        } else if (strcasecmp(output, "both") == 0) {
            new_output = LOG_OUTPUT_BOTH;
        } else if (strcasecmp(output, "file") == 0) {
            new_output = LOG_OUTPUT_FILE;
        } else {
            new_output = LOG_OUTPUT_STDOUT;
        }
        atomic_store(&output_mode, new_output);
    }

    /* Apply per-service levels */
    const char *imap_level = get_config_value("logging", "imap_level");
    if (imap_level)
        log_set_level("imap", parse_level(imap_level));
    const char *pop3_level = get_config_value("logging", "pop3_level");
    if (pop3_level)
        log_set_level("pop3", parse_level(pop3_level));
    const char *db_level = get_config_value("logging", "db_level");
    if (db_level)
        log_set_level("db", parse_level(db_level));

    return 0;
}

void log_set_level(const char *service, log_level_t level) {
    pthread_mutex_lock(&svc_lock);
    for (int i = 0; i < svc_levels_count; i++) {
        if (strncmp(svc_levels[i].name, service, SERVICE_NAME_LEN) == 0) {
            svc_levels[i].level = level;
            pthread_mutex_unlock(&svc_lock);
            return;
        }
    }
    if (svc_levels_count < (int)(sizeof(svc_levels) / sizeof(svc_levels[0]))) {
        strncpy(svc_levels[svc_levels_count].name, service, SERVICE_NAME_LEN - 1);
        svc_levels[svc_levels_count].name[SERVICE_NAME_LEN - 1] = '\0';
        svc_levels[svc_levels_count].level = level;
        svc_levels_count++;
    }
    pthread_mutex_unlock(&svc_lock);
}

static log_level_t get_service_level(const char *service) {
    pthread_mutex_lock(&svc_lock);
    for (int i = 0; i < svc_levels_count; i++) {
        if (strncmp(svc_levels[i].name, service, SERVICE_NAME_LEN) == 0) {
            log_level_t l = svc_levels[i].level;
            pthread_mutex_unlock(&svc_lock);
            return l;
        }
    }
    pthread_mutex_unlock(&svc_lock);
    return default_level;
}

void log_emit(log_level_t level, const char *fmt, ...) {
    if (!atomic_load(&running)) {
        /* Log system not initialized - fall back to stderr for critical errors */
        if (level >= LOG_LEVEL_ERROR) {
            va_list ap;
            va_start(ap, fmt);
            vfprintf(stderr, fmt, ap);
            fprintf(stderr, "\n");
            va_end(ap);
        }
        return;
    }

    unsigned int h = atomic_fetch_add(&head, 1u);
    unsigned int t = atomic_load(&tail);
    if (h - t >= RING_SIZE) {
        /* ring full, drop */
        atomic_fetch_sub(&head, 1u);
        atomic_fetch_add(&dropped, 1u);
        return;
    }

    struct log_entry *e = &ring[h & RING_MASK];
    e->ts_ns = now_ns();
    e->level = level;

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->msg, MSG_LEN, fmt, ap);
    va_end(ap);

    /* wake flusher */
    pthread_mutex_lock(&flusher_lock);
    pthread_cond_signal(&flusher_cond);
    pthread_mutex_unlock(&flusher_lock);
}

/* diagnostic: returns number of dropped messages */
unsigned int log_dropped_count(void) {
    return atomic_load(&dropped);
}