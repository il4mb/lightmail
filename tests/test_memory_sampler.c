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

    if (memory_sampler_init(1) != 0) {
        fprintf(stderr, "memory_sampler_init failed\n");
        metrics_shutdown();
        return 1;
    }

    /* Poll /metrics up to 2s for sampler to record a metric */
    int port = metrics_get_listen_port();
    if (port <= 0) { fprintf(stderr, "invalid metrics port %d\n", port); memory_sampler_shutdown(); metrics_shutdown(); return 1; }

    int found = 0;
    for (int i = 0; i < 20; i++) {
        usleep(100 * 1000);
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(sock); continue; }

        const char *req = "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
        write(sock, req, strlen(req));
        char buf[4096]; ssize_t n = read(sock, buf, sizeof(buf)-1);
        if (n <= 0) { close(sock); continue; }
        buf[n] = '\0'; close(sock);
        if (strstr(buf, "lightmail_memory_pressure_bytes") != NULL) { found = 1; break; }
    }

    if (!found) {
        fprintf(stderr, "memory metric missing\n");
        memory_sampler_shutdown(); metrics_shutdown(); return 1; }

    memory_sampler_shutdown();
    metrics_shutdown();
    printf("OK\n");
    return 0;
}
