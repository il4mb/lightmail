#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../include/metrics.h"
#include "../include/lmtp_queue.h"

/* Stub s3 uploader used only for test linking */
char *s3_upload_message_file(int account_id, int mailbox_id, int message_uid, FILE *file, size_t size, const char *content_type) {
    /* Simulate some processing time */
    usleep(100 * 1000);
    char *k = NULL;
    if (asprintf(&k, "stub/acc%d/mb%d/msg%d.eml", account_id, mailbox_id, message_uid) < 0) return NULL;
    return k;
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

    /* Create a temporary file to simulate message */
    char tmp_template[] = "/tmp/lightmail_testmsg_XXXXXX";
    int fd = mkstemp(tmp_template);
    if (fd < 0) { perror("mkstemp"); return 1; }
    write(fd, "hello", 5);
    close(fd);

    /* Enqueue */
    if (lmtp_queue_enqueue(tmp_template, 1, 1, 1, 5) != 0) {
        fprintf(stderr, "enqueue failed\n");
        unlink(tmp_template);
        lmtp_queue_shutdown();
        metrics_shutdown();
        return 1;
    }

    /* After enqueue, hit /metrics to ensure lmtp queue depth and s3 counter appear */
    int port = metrics_get_listen_port();
    if (port <= 0) { fprintf(stderr, "invalid metrics port %d\n", port); return 1; }

    /* Wait briefly for worker to process job */
    sleep(1);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("connect"); return 1; }
    const char *req = "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
    write(sock, req, strlen(req));
    char buf[4096]; ssize_t n = read(sock, buf, sizeof(buf)-1);
    if (n <= 0) { perror("read"); close(sock); return 1; }
    buf[n] = '\0'; close(sock);

    if (strstr(buf, "lightmail_s3_uploads_total") == NULL) {
        fprintf(stderr, "s3 uploads counter missing\n");
        lmtp_queue_shutdown(); metrics_shutdown(); return 1;
    }

    /* cleanup */
    lmtp_queue_shutdown();
    metrics_shutdown();
    printf("OK\n");
    return 0;
}
