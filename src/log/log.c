#define _GNU_SOURCE
#include "log.h"
#include "conf.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <stdatomic.h>
#include <limits.h>

static char current_path[PATH_MAX] = "";

static log_level_t parse_level(const char *s) {
    if (!s) return LOG_LEVEL_INFO;
    if (strcasecmp(s, "DEBUG") == 0) return LOG_LEVEL_DEBUG;
    if (strcasecmp(s, "INFO") == 0) return LOG_LEVEL_INFO;
    if (strcasecmp(s, "WARN") == 0) return LOG_LEVEL_WARN;
    if (strcasecmp(s, "ERROR") == 0) return LOG_LEVEL_ERROR;
    if (strcasecmp(s, "CRITICAL") == 0) return LOG_LEVEL_CRITICAL;
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
    char service[SERVICE_NAME_LEN];
    pid_t pid;
    char user[USER_LEN];
    char session[SESSION_LEN];
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

/* simple service level mapping */
struct svc_level { char name[SERVICE_NAME_LEN]; log_level_t level; };
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
    case LOG_LEVEL_DEBUG: return "DEBUG";
    case LOG_LEVEL_INFO: return "INFO";
    case LOG_LEVEL_WARN: return "WARN";
    case LOG_LEVEL_ERROR: return "ERROR";
    case LOG_LEVEL_CRITICAL: return "CRITICAL";
    default: return "UNKNOWN";
    }
}

static void flusher_run(void) {
    while (atomic_load(&running)) {
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
            /* format JSON line */
            char buf[1024];
            int n = snprintf(buf, sizeof(buf), "{\"ts\":%llu,\"level\":\"%s\",\"service\":\"%s\",\"pid\":%d,\"user\":\"%s\",\"session\":\"%s\",\"msg\":\"%s\"}\n",
                (unsigned long long)e->ts_ns,
                level_to_str(e->level),
                e->service,
                (int)e->pid,
                e->user[0] ? e->user : "",
                e->session[0] ? e->session : "",
                e->msg);
            if (n > 0) {
                ssize_t r = write(out_fd, buf, (size_t)n);
                (void)r; /* ignore write errors for now */
            }
            atomic_store(&tail, t + 1);
        }
    }

    /* drain remaining entries on shutdown */
    unsigned int t = atomic_load(&tail);
    unsigned int h = atomic_load(&head);
    while (t != h) {
        struct log_entry *e = &ring[t & RING_MASK];
        char buf[1024];
        int n = snprintf(buf, sizeof(buf), "{\"ts\":%llu,\"level\":\"%s\",\"service\":\"%s\",\"pid\":%d,\"user\":\"%s\",\"session\":\"%s\",\"msg\":\"%s\"}\n",
            (unsigned long long)e->ts_ns,
            level_to_str(e->level),
            e->service,
            (int)e->pid,
            e->user[0] ? e->user : "",
            e->session[0] ? e->session : "",
            e->msg);
        if (n > 0) {
            ssize_t r = write(out_fd, buf, (size_t)n);
            (void)r;
        }
        t++;
    }
}

static void *flusher_thread_main(void *arg) {
    (void)arg;
    flusher_run();
    return NULL;
}

int log_init(const char *path) {
    if (atomic_load(&running)) return 0; /* already started */

    if (path) {
        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) return -1;
        out_fd = fd;
    } else {
        out_fd = STDOUT_FILENO;
    }

    atomic_store(&running, 1);
    atomic_store(&head, 0);
    atomic_store(&tail, 0);
    pthread_create(&flusher_thread, NULL, flusher_thread_main, NULL);
    return 0;
}

void log_close(void) {
    if (!atomic_load(&running)) return;
    atomic_store(&running, 0);
    pthread_mutex_lock(&flusher_lock);
    pthread_cond_signal(&flusher_cond);
    pthread_mutex_unlock(&flusher_lock);
    pthread_join(flusher_thread, NULL);
    if (out_fd != STDOUT_FILENO && out_fd >= 0) close(out_fd);
}

int log_reload_config(void) {
    const char *path = get_config_value("logging", "path");
    const char *level = get_config_value("logging", "level");

    /* Reopen path if changed */
    if (path && (current_path[0] == '\0' || strcmp(current_path, path) != 0)) {
        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            if (out_fd != STDOUT_FILENO && out_fd >= 0) close(out_fd);
            out_fd = fd;
            strncpy(current_path, path, sizeof(current_path)-1);
            current_path[sizeof(current_path)-1] = '\0';
        } else {
            /* Could not open new path, keep old */
        }
    }

    /* Apply default level */
    if (level) {
        default_level = parse_level(level);
    }

    /* Apply per-service levels */
    const char *imap_level = get_config_value("logging", "imap_level");
    if (imap_level) log_set_level("imap", parse_level(imap_level));
    const char *pop3_level = get_config_value("logging", "pop3_level");
    if (pop3_level) log_set_level("pop3", parse_level(pop3_level));
    const char *db_level = get_config_value("logging", "db_level");
    if (db_level) log_set_level("db", parse_level(db_level));

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
    if (svc_levels_count < (int)(sizeof(svc_levels)/sizeof(svc_levels[0]))) {
        strncpy(svc_levels[svc_levels_count].name, service, SERVICE_NAME_LEN-1);
        svc_levels[svc_levels_count].name[SERVICE_NAME_LEN-1] = '\0';
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

void log_emit(log_level_t level, const char *service, const char *user, const char *session, const char *fmt, ...) {
    if (!service) service = "main";
    if (level < get_service_level(service)) return;

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
    e->pid = getpid();
    strncpy(e->service, service, SERVICE_NAME_LEN-1);
    e->service[SERVICE_NAME_LEN-1] = '\0';
    if (user) {
        strncpy(e->user, user, USER_LEN-1);
        e->user[USER_LEN-1] = '\0';
    } else {
        e->user[0] = '\0';
    }
    if (session) {
        strncpy(e->session, session, SESSION_LEN-1);
        e->session[SESSION_LEN-1] = '\0';
    } else {
        e->session[0] = '\0';
    }

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
