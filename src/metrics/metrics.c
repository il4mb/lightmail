#define _GNU_SOURCE
#include "metrics.h"
#include <lightmail.h>
#include "log.h"
#include <stdatomic.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

static atomic_uint_fast64_t imap_sessions = 0;
static atomic_uint_fast64_t auth_failures = 0;
static atomic_uint_fast64_t spam_rejections = 0;
static atomic_uint_fast64_t lmtp_queue_depth = 0;
static atomic_uint_fast64_t s3_upload_count = 0;
static atomic_uint_fast64_t s3_upload_total_ms = 0;
static atomic_uint_fast64_t mysql_query_count = 0;
static atomic_uint_fast64_t mysql_query_total_ms = 0;
static atomic_uint_fast64_t memory_pressure_bytes = 0;

static int metrics_port = 0;
static int metric_sock = -1;
static pthread_t metrics_thread;
static atomic_int metrics_running = 0;

static void write_metrics_to_fd(int fd) {
    char buf[4096];
    int len = snprintf(buf, sizeof(buf),
        "# HELP lightmail_imap_sessions Active IMAP sessions\n"
        "# TYPE lightmail_imap_sessions gauge\n"
        "lightmail_imap_sessions %llu\n"
        "# HELP lightmail_auth_failures Authentication failures\n"
        "# TYPE lightmail_auth_failures counter\n"
        "lightmail_auth_failures %llu\n"
        "# HELP lightmail_spam_rejections Spam rejections\n"
        "# TYPE lightmail_spam_rejections counter\n"
        "lightmail_spam_rejections %llu\n"
        "# HELP lightmail_lmtp_queue_depth LMTP queue depth\n"
        "# TYPE lightmail_lmtp_queue_depth gauge\n"
        "lightmail_lmtp_queue_depth %llu\n"
        "# HELP lightmail_s3_uploads_total S3 uploads total\n"
        "# TYPE lightmail_s3_uploads_total counter\n"
        "lightmail_s3_uploads_total %llu\n"
        "# HELP lightmail_s3_upload_duration_ms_total S3 upload duration sum (ms)\n"
        "# TYPE lightmail_s3_upload_duration_ms_total counter\n"
        "lightmail_s3_upload_duration_ms_total %llu\n"
        "# HELP lightmail_mysql_query_duration_ms_total MySQL query duration sum (ms)\n"
        "# TYPE lightmail_mysql_query_duration_ms_total counter\n"
        "lightmail_mysql_query_duration_ms_total %llu\n"
        "# HELP lightmail_memory_pressure_bytes Memory pressure observed (bytes)\n"
        "# TYPE lightmail_memory_pressure_bytes gauge\n"
        "lightmail_memory_pressure_bytes %llu\n",
        (unsigned long long)atomic_load(&imap_sessions),
        (unsigned long long)atomic_load(&auth_failures),
        (unsigned long long)atomic_load(&spam_rejections),
        (unsigned long long)atomic_load(&lmtp_queue_depth),
        (unsigned long long)atomic_load(&s3_upload_count),
        (unsigned long long)atomic_load(&s3_upload_total_ms),
        (unsigned long long)atomic_load(&mysql_query_total_ms),
        (unsigned long long)atomic_load(&memory_pressure_bytes)
    );

    if (len > 0) write(fd, buf, (size_t)len);
}

static void *metrics_thread_main(void *arg) {
    (void)arg;
    while (atomic_load(&metrics_running)) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int fd = accept(metric_sock, (struct sockaddr *)&client_addr, &addrlen);
        if (fd < 0) {
            usleep(100000);
            continue;
        }

        /* read request (ignore content) */
        char req[1024];
        ssize_t n = read(fd, req, sizeof(req)-1);
        (void)n;
        /* simple response */
        const char *header = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nConnection: close\r\n\r\n";
        write(fd, header, strlen(header));
        write_metrics_to_fd(fd);
        close(fd);
    }
    return NULL;
}

int metrics_init(int port) {
    /* Allow port 0 to mean 'ephemeral' */
    metrics_port = port;

    metric_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (metric_sock < 0) return -1;

    int opt = 1;
    setsockopt(metric_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* bind to loopback */
    addr.sin_port = htons((uint16_t)port);

    if (bind(metric_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(metric_sock);
        metric_sock = -1;
        return -1;
    }

    /* If port was 0 (ephemeral), read the assigned port */
    if (port == 0) {
        struct sockaddr_in bound = {0};
        socklen_t len = sizeof(bound);
        if (getsockname(metric_sock, (struct sockaddr *)&bound, &len) == 0) {
            metrics_port = ntohs(bound.sin_port);
        }
    }

    if (listen(metric_sock, 4) < 0) {
        close(metric_sock);
        metric_sock = -1;
        return -1;
    }

    atomic_store(&metrics_running, 1);
    if (pthread_create(&metrics_thread, NULL, metrics_thread_main, NULL) != 0) {
        atomic_store(&metrics_running, 0);
        close(metric_sock);
        metric_sock = -1;
        return -1;
    }

    LOGI("metrics", "Metrics server started on port %d", metrics_port);
    return 0;
}

int metrics_get_listen_port(void) {
    return metrics_port;
}

void metrics_shutdown(void) {
    if (!metric_sock) return;
    atomic_store(&metrics_running, 0);
    shutdown(metric_sock, SHUT_RDWR);
    close(metric_sock);
    metric_sock = -1;
    pthread_join(metrics_thread, NULL);
}

/* Counters */
void metrics_inc_imap_sessions(void) { atomic_fetch_add(&imap_sessions, 1); }
void metrics_dec_imap_sessions(void) { atomic_fetch_sub(&imap_sessions, 1); }
void metrics_inc_auth_failures(void) { atomic_fetch_add(&auth_failures, 1); }
void metrics_inc_spam_rejections(void) { atomic_fetch_add(&spam_rejections, 1); }
void metrics_set_lmtp_queue_depth(uint64_t v) { atomic_store(&lmtp_queue_depth, v); }
void metrics_inc_lmtp_queue_depth(void) { atomic_fetch_add(&lmtp_queue_depth, 1); }
void metrics_dec_lmtp_queue_depth(void) { atomic_fetch_sub(&lmtp_queue_depth, 1); }
void metrics_record_s3_upload_ms(uint64_t ms) { atomic_fetch_add(&s3_upload_count, 1); atomic_fetch_add(&s3_upload_total_ms, ms); }
void metrics_record_mysql_query_ms(uint64_t ms) { atomic_fetch_add(&mysql_query_count, 1); atomic_fetch_add(&mysql_query_total_ms, ms); }
void metrics_record_memory_pressure_bytes(uint64_t bytes) { atomic_store(&memory_pressure_bytes, bytes); }
