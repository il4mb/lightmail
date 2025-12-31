#include "lmtp.h"
#include "lmtp_session.h"
#include "log.h"
#include "conf.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define LMTP_BACKLOG 20

// TODO: The current implementation is a single-threaded, iterative server.
// For production, this should be converted to a multi-threaded or
// event-driven (e.g., epoll, kqueue) model to handle concurrent connections.

int start_lmtp(void) {
    int server_fd;
    struct sockaddr_un server_addr;

    const char* socket_path = get_config_value("lmtp", "socket_path");
    if (!socket_path) socket_path = "/var/run/lightmail/lmtp.sock";

    // Create a UNIX domain socket
    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        log_emit(LOG_LEVEL_CRITICAL, "lmtp", NULL, NULL, "Failed to create socket: %s", strerror(errno));
        return -1;
    }

    // Unlink the socket path in case it already exists
    unlink(socket_path);

    // Setup the address structure
    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, socket_path, sizeof(server_addr.sun_path) - 1);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr_un)) == -1) {
        log_emit(LOG_LEVEL_CRITICAL, "lmtp", NULL, NULL, "Failed to bind socket %s: %s", socket_path, strerror(errno));
        close(server_fd);
        return -1;
    }

    // Listen for incoming connections
    if (listen(server_fd, LMTP_BACKLOG) == -1) {
        log_emit(LOG_LEVEL_CRITICAL, "lmtp", NULL, NULL, "Failed to listen on socket %s: %s", socket_path, strerror(errno));
        close(server_fd);
        return -1;
    }

    log_emit(LOG_LEVEL_INFO, "lmtp", NULL, NULL, "LMTP server listening on %s", socket_path);

    // Main accept loop
    while (1) {
        int client_fd;
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(struct sockaddr_un);

        if ((client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len)) == -1) {
            log_emit(LOG_LEVEL_ERROR, "lmtp", NULL, NULL, "Failed to accept connection: %s", strerror(errno));
            // Depending on the error, we might want to break the loop
            continue;
        }

        /* Metrics: increment LMTP active queue/sessions */
        metrics_inc_lmtp_queue_depth();

        // For now, handle the session sequentially.
        handle_lmtp_session(client_fd);

        /* After session ends, decrement the LMTP queue */
        metrics_dec_lmtp_queue_depth();
    }

    // Cleanup
    close(server_fd);
    unlink(socket_path);

    return 0;
}
