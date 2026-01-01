#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include "../include/db.h"
#include "../include/lmtp_queue.h"
#include "../include/metrics.h"

/* Minimal stub s3 uploader */
char *s3_upload_message_file(int account_id, int mailbox_id, int message_uid, FILE *file, size_t size, const char *content_type) {
    /* Simulate some processing time */
    usleep(200 * 1000);
    char *k = NULL;
    if (asprintf(&k, "stub/acc%d/mb%d/msg%d.eml", account_id, mailbox_id, message_uid) < 0) return NULL;
    return k;
}

/* Minimal DB/S3 stubs so queue worker can link */
bool db_store_message(Message *m) { (void)m; return true; }
void db_free_message(Message *m) { (void)m; }
bool s3_delete_message(const char *s3_key) { (void)s3_key; return true; }

int main(void) {
    if (metrics_init(0) != 0) { fprintf(stderr, "metrics_init failed\n"); return 1; }
    /* Use capacity 1 to avoid race with the worker thread */
    if (lmtp_queue_init(1) != 0) { fprintf(stderr, "lmtp_queue_init failed\n"); metrics_shutdown(); return 1; }

    /* Set non-blocking enqueue (timeout 0) - default behavior */
    lmtp_queue_set_enqueue_timeout_ms(0);

    /* create two temp files: first should succeed, second should fail immediately */
    char t1[] = "/tmp/sat_XXXXXX"; int fd1 = mkstemp(t1); write(fd1, "a",1); close(fd1);
    char t2[] = "/tmp/sat_XXXXXX"; int fd2 = mkstemp(t2); write(fd2, "b",1); close(fd2);

    if (lmtp_queue_enqueue(t1, 1,1,1,1) != 0) { fprintf(stderr, "enqueue1 failed\n"); lmtp_queue_shutdown(); metrics_shutdown(); return 1; }
    if (lmtp_queue_enqueue(t2, 1,1,1,1) == 0) { fprintf(stderr, "enqueue2 should have failed but succeeded\n"); lmtp_queue_shutdown(); metrics_shutdown(); return 1; }

    /* Now set a small timeout and attempt enqueue; should wait and succeed after worker processes one */
    lmtp_queue_set_enqueue_timeout_ms(1000); /* 1s */
    char t3[] = "/tmp/sat_XXXXXX"; int fd3 = mkstemp(t3); write(fd3, "c",1); close(fd3);
    if (lmtp_queue_enqueue(t3, 1,1,1,1) != 0) { fprintf(stderr, "enqueue with timeout failed\n"); lmtp_queue_shutdown(); metrics_shutdown(); return 1; }

    /* cleanup */
    lmtp_queue_shutdown();
    metrics_shutdown();
    printf("OK\n");
    return 0;
}
