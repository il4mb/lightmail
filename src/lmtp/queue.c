#include "lmtp_queue.h"
#include "log.h"
#include "metrics.h"
#include "s3.h"
#include "db.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

typedef struct {
    char *path;
    int account_id;
    int mailbox_id;
    int message_uid;
    size_t size;
} lmtp_job_t;

static lmtp_job_t *g_queue = NULL;
static size_t g_cap = 0;
static size_t g_head = 0;
static size_t g_tail = 0;
static size_t g_count = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_not_empty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t g_not_full = PTHREAD_COND_INITIALIZER;
static pthread_t g_worker;
static int g_running = 0;
static int g_enqueue_timeout_ms = 0; /* 0 = no-wait (immediate failure when full) */

static void _free_job(lmtp_job_t *job) {
    if (!job) return;
    free(job->path);
}

static void *_worker_main(void *arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&g_lock);
        while (g_count == 0 && g_running) {
            pthread_cond_wait(&g_not_empty, &g_lock);
        }
        if (!g_running && g_count == 0) {
            pthread_mutex_unlock(&g_lock);
            break;
        }
        lmtp_job_t job = g_queue[g_head];
        g_queue[g_head].path = NULL; /* ownership transferred */
        g_head = (g_head + 1) % g_cap;
        g_count--;
        /* signal producers waiting for free space */
        pthread_cond_signal(&g_not_full);
        pthread_mutex_unlock(&g_lock);

        /* We dequeued one job: update metrics */
        metrics_dec_lmtp_queue_depth();

        /* Process job */
        FILE *f = fopen(job.path, "rb");
        if (!f) {
            log_emit(LOG_LEVEL_ERROR, "lmtp", NULL, NULL, "Worker failed to open job file %s", job.path);
            _free_job(&job);
            continue;
        }

        /* perform s3 upload (s3_upload_message_file returns key on success) */
        char *key = s3_upload_message_file(job.account_id, job.mailbox_id, job.message_uid, f, job.size, "application/octet-stream");
        fclose(f);

        if (key) {
            log_emit(LOG_LEVEL_INFO, "lmtp", NULL, NULL, "Worker uploaded job file %s -> s3=%s", job.path, key);

            /* Build Message metadata and persist to DB */
            Message *m = calloc(1, sizeof(Message));
            if (m) {
                m->mailbox_id = job.mailbox_id;
                int next_uid = db_get_next_uid(job.mailbox_id);
                m->uid = (next_uid > 0) ? next_uid : job.message_uid;
                m->internal_date = time(NULL);
                m->flags = strdup("");
                m->size = job.size;
                m->envelope_from = strdup("");
                m->envelope_to = strdup("");
                m->envelope_subject = strdup("");
                m->envelope_message_id = strdup("");
                m->body_s3_key = strdup(key);
                m->body_size = (int)job.size;
                m->mime_type = strdup("application/octet-stream");
                m->encoding = strdup("");

                if (db_store_message(m)) {
                    log_emit(LOG_LEVEL_INFO, "lmtp", NULL, NULL, "Worker stored message metadata mailbox=%d uid=%d s3=%s", m->mailbox_id, m->uid, m->body_s3_key);
                } else {
                    log_emit(LOG_LEVEL_ERROR, "lmtp", NULL, NULL, "Worker failed to store message in DB, deleting s3=%s", key);
                    if (!s3_delete_message(key)) {
                        log_emit(LOG_LEVEL_ERROR, "lmtp", NULL, NULL, "Worker failed to delete s3 object %s after DB failure", key);
                    }
                }

                db_free_message(m);
            } else {
                log_emit(LOG_LEVEL_ERROR, "lmtp", NULL, NULL, "Worker failed to allocate Message struct for %s", key);
            }

            free(key);
        } else {
            log_emit(LOG_LEVEL_ERROR, "lmtp", NULL, NULL, "Worker failed to upload job file %s to S3", job.path);
        }

        /* remove temp file */
        unlink(job.path);
        _free_job(&job);

        /* small yield */
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10000000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

int lmtp_queue_init(size_t capacity) {
    if (capacity == 0) capacity = 16;
    g_queue = calloc(capacity, sizeof(lmtp_job_t));
    if (!g_queue) return -1;
    g_cap = capacity;
    g_head = g_tail = g_count = 0;
    g_running = 1;
    g_enqueue_timeout_ms = 0;
    pthread_cond_init(&g_not_full, NULL);
    if (pthread_create(&g_worker, NULL, _worker_main, NULL) != 0) {
        g_running = 0;
        pthread_cond_destroy(&g_not_full);
        free(g_queue);
        g_queue = NULL;
        return -1;
    }
    return 0;
}

void lmtp_queue_shutdown(void) {
    pthread_mutex_lock(&g_lock);
    g_running = 0;
    pthread_cond_signal(&g_not_empty);
    pthread_cond_signal(&g_not_full);
    pthread_mutex_unlock(&g_lock);
    pthread_join(g_worker, NULL);

    /* free remaining jobs */
    for (size_t i = 0; i < g_count; i++) {
        size_t idx = (g_head + i) % g_cap;
        _free_job(&g_queue[idx]);
    }
    free(g_queue);
    g_queue = NULL;
    g_cap = 0;
    g_head = g_tail = g_count = 0;
}


void lmtp_queue_set_enqueue_timeout_ms(int ms) {
    pthread_mutex_lock(&g_lock);
    g_enqueue_timeout_ms = ms;
    pthread_mutex_unlock(&g_lock);
}

int lmtp_queue_enqueue(const char *path, int account_id, int mailbox_id, int message_uid, size_t size) {
    if (!g_queue) return -1;
    pthread_mutex_lock(&g_lock);
    if (g_count == g_cap) {
        if (g_enqueue_timeout_ms == 0) {
            pthread_mutex_unlock(&g_lock);
            return -1; /* immediate failure when full */
        }
        /* Wait up to timeout for space */
        struct timespec now, abs_timeout;
        clock_gettime(CLOCK_REALTIME, &now);
        abs_timeout.tv_sec = now.tv_sec + (g_enqueue_timeout_ms / 1000);
        abs_timeout.tv_nsec = now.tv_nsec + (g_enqueue_timeout_ms % 1000) * 1000000;
        if (abs_timeout.tv_nsec >= 1000000000) {
            abs_timeout.tv_sec += 1;
            abs_timeout.tv_nsec -= 1000000000;
        }

        int rc = 0;
        while (g_count == g_cap && rc == 0) {
            rc = pthread_cond_timedwait(&g_not_full, &g_lock, &abs_timeout);
        }
        if (g_count == g_cap) {
            pthread_mutex_unlock(&g_lock);
            return -1; /* still full after timeout */
        }
    }
    lmtp_job_t job = {0};
    job.path = strdup(path);
    job.account_id = account_id;
    job.mailbox_id = mailbox_id;
    job.message_uid = message_uid;
    job.size = size;
    g_queue[g_tail] = job;
    g_tail = (g_tail + 1) % g_cap;
    g_count++;
    pthread_cond_signal(&g_not_empty);
    pthread_mutex_unlock(&g_lock);

    /* Metrics: increment queue depth */
    metrics_inc_lmtp_queue_depth();
    return 0;
}