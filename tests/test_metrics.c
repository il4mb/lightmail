#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../include/metrics.h"

int main(void) {
    if (metrics_init(0) != 0) {
        fprintf(stderr, "metrics_init failed\n");
        return 1;
    }

    int port = metrics_get_listen_port();
    if (port <= 0) {
        fprintf(stderr, "Invalid metrics port %d\n", port);
        metrics_shutdown();
        return 1;
    }

    /* increment one session */
    metrics_inc_imap_sessions();

    /* record example S3 and MySQL timings */
    metrics_record_s3_upload_ms(123);
    metrics_record_mysql_query_ms(77);

    /* set LMTP queue depth */
    metrics_set_lmtp_queue_depth(3);

    /* connect and fetch /metrics */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        metrics_shutdown();
        return 1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        metrics_shutdown();
        return 1;
    }

    const char *req = "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
    if (write(sock, req, strlen(req)) < 0) {
        perror("write");
        close(sock);
        metrics_shutdown();
        return 1;
    }

    char buf[8192];
    ssize_t total = 0;
    while (1) {
        ssize_t n = read(sock, buf + total, sizeof(buf) - 1 - total);
        if (n <= 0) break;
        total += n;
        if (total >= (ssize_t)sizeof(buf) - 1) break;
    }
    if (total <= 0) {
        perror("read");
        close(sock);
        metrics_shutdown();
        return 1;
    }
    buf[total] = '\0';
    close(sock);

    /* check that the metrics contains our gauge */
    if (strstr(buf, "lightmail_imap_sessions") == NULL) {
        fprintf(stderr, "metrics output missing imap_sessions\n");
        metrics_shutdown();
        return 1;
    }

    if (strstr(buf, "lightmail_imap_sessions 1") == NULL && strstr(buf, "lightmail_imap_sessions 1.0") == NULL) {
        fprintf(stderr, "unexpected imap_sessions value:\n%s\n", buf);
        metrics_shutdown();
        return 1;
    }

    /* check S3 metrics */
    if (strstr(buf, "lightmail_s3_uploads_total") == NULL) {
        fprintf(stderr, "metrics output missing s3 uploads counter\n");
        metrics_shutdown();
        return 1;
    }
    if (strstr(buf, "lightmail_s3_upload_duration_ms_total") == NULL) {
        fprintf(stderr, "metrics output missing s3 duration metric\n");
        metrics_shutdown();
        return 1;
    }

    /* check MySQL metrics */
    if (strstr(buf, "lightmail_mysql_query_duration_ms_total") == NULL) {
        fprintf(stderr, "metrics output missing mysql duration metric\n");
        metrics_shutdown();
        return 1;
    }

    /* check LMTP queue depth */
    if (strstr(buf, "lightmail_lmtp_queue_depth") == NULL) {
        fprintf(stderr, "metrics output missing lmtp queue depth metric\n");
        metrics_shutdown();
        return 1;
    }
    if (strstr(buf, "lightmail_lmtp_queue_depth 3") == NULL && strstr(buf, "lightmail_lmtp_queue_depth 3.0") == NULL) {
        fprintf(stderr, "unexpected lmtp_queue_depth value:\n%s\n", buf);
        metrics_shutdown();
        return 1;
    }

    metrics_shutdown();
    printf("OK\n");
    return 0;
}
