#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../include/lmtp_queue.h"
#include "../include/metrics.h"
#include "../include/db.h"

/* Control flags observed by stubs */
static int db_should_succeed = 1;
static int db_store_called = 0;
static int s3_delete_called = 0;

/* Stub s3 uploader used only for test linking */
char *s3_upload_message_file(int account_id, int mailbox_id, int message_uid, FILE *file, size_t size, const char *content_type) {
    usleep(100 * 1000);
    char *k = NULL;
    if (asprintf(&k, "stub/acc%d/mb%d/msg%d.eml", account_id, mailbox_id, message_uid) < 0) return NULL;
    return k;
}

bool s3_delete_message(const char *s3_key) {
    (void)s3_key;
    s3_delete_called = 1;
    return true;
}

int db_get_next_uid(int mailbox_id) {
    (void)mailbox_id;
    return 100;
}

int db_allocate_uid(int mailbox_id) {
    (void)mailbox_id;
    return 100;
}

bool db_store_message(Message *m) {
    (void)m;
    db_store_called = 1;
    return db_should_succeed ? true : false;
}

void db_free_message(Message *m) {
    (void)m; /* tests don't need to free contents */
}

int main(void) {
    if (metrics_init(0) != 0) {
        fprintf(stderr, "metrics_init failed\n");
        return 1;
    }

    if (lmtp_queue_init(4) != 0) {
        fprintf(stderr, "lmtp_queue_init failed\n");
        metrics_shutdown();
        return 1;
    }

    /* Scenario 1: DB success */
    db_should_succeed = 1;
    db_store_called = 0;
    s3_delete_called = 0;

    char tmp1[] = "/tmp/lightmail_testmsg_XXXXXX";
    int fd1 = mkstemp(tmp1);
    if (fd1 < 0) { perror("mkstemp"); return 1; }
    write(fd1, "hello", 5);
    close(fd1);

    if (lmtp_queue_enqueue(tmp1, 1, 1, 1, 5) != 0) { fprintf(stderr, "enqueue failed\n"); unlink(tmp1); lmtp_queue_shutdown(); metrics_shutdown(); return 1; }

    sleep(1);
    if (!db_store_called) { fprintf(stderr, "db_store_message was not called in success case\n"); lmtp_queue_shutdown(); metrics_shutdown(); return 1; }
    if (s3_delete_called) { fprintf(stderr, "s3_delete should not have been called in success case\n"); lmtp_queue_shutdown(); metrics_shutdown(); return 1; }

    /* Scenario 2: DB failure -> S3 delete invoked */
    db_should_succeed = 0;
    db_store_called = 0;
    s3_delete_called = 0;

    char tmp2[] = "/tmp/lightmail_testmsg_XXXXXX";
    int fd2 = mkstemp(tmp2);
    if (fd2 < 0) { perror("mkstemp"); return 1; }
    write(fd2, "hello", 5);
    close(fd2);

    if (lmtp_queue_enqueue(tmp2, 2, 2, 2, 5) != 0) { fprintf(stderr, "enqueue failed\n"); unlink(tmp2); lmtp_queue_shutdown(); metrics_shutdown(); return 1; }

    sleep(1);
    if (!db_store_called) { fprintf(stderr, "db_store_message was not called in failure case\n"); lmtp_queue_shutdown(); metrics_shutdown(); return 1; }
    if (!s3_delete_called) { fprintf(stderr, "s3_delete_message was not called after DB failure\n"); lmtp_queue_shutdown(); metrics_shutdown(); return 1; }

    lmtp_queue_shutdown();
    metrics_shutdown();
    printf("OK\n");
    return 0;
}
