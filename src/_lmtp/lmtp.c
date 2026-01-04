#include "lmtp.h"
#include "lightmail.h"
#include "lmtp_session.h"
#include "log.h"
#include "metrics.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define LMTP_BACKLOG 20

int lmtp_start(void) {

    int server_fd;
    struct sockaddr_un server_addr;

    const char *socket_path = get_config_value("lmtp", "socket");
    if (!socket_path)
        socket_path = "/var/run/lightmail/lmtp.sock";

    // Create a UNIX domain socket
    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        LOGE("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    // Unlink the socket path in case it already exists
    unlink(socket_path);

    // Setup the address structure
    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, socket_path, sizeof(server_addr.sun_path) - 1);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) == -1) {
        LOGE("Failed to bind socket %s: %s", socket_path);
        close(server_fd);
        return -1;
    }

    // Listen for incoming connections
    if (listen(server_fd, LMTP_BACKLOG) == -1) {
        LOGE("Failed to listen on socket %s: %s", socket_path);
        close(server_fd);
        return -1;
    }

    LOGI("LMTP server listening on %s", socket_path);

    // Main accept loop
    while (1) {
        int client_fd;
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(struct sockaddr_un);

        if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len)) == -1) {
            LOGE("Filed to accept connection: %s", strerror(errno));
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

    LOGI("LMTP server stopped");
    // Cleanup
    close(server_fd);
    unlink(socket_path);

    return 0;
}
