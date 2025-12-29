#include "imap.h"
#include "db.h"
#include "mailbox.h"
#include "s3.h"
#include "log.h"
#include "shutdown.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <conf.h>

#define MAX_TAG_LENGTH 64
#define MAX_COMMAND_LENGTH 64
#define MAX_RESPONSE_LENGTH 4096
#define SESSION_TIMEOUT 1800

bool IS_IMAP_RUNNING = false;

int start_imap() {

    setup_signal_handlers();

    const ServerConfig *cfg = get_config();

    int port = cfg->imap_port;
    int port_ssl = cfg->imaps_port;
    int imap_socket;
    
    IS_IMAP_RUNNING = true;
    printf("Starting IMAP server on port %d (IMAP) and %d (IMAPS)...\n", port, port_ssl);
    LOGD("IMAP server started. Listening on port %d (IMAP) and %d (IMAPS).", port, port_ssl);
    while (!g_shutdown) {
        sleep(1);
    }

    // send_response(client, "* BYE Server shutting down\r\n", 30, 0);

    printf("IMAP server stopped.\n");
    LOGD("IMAP server stopped.");
    return 0;
}

bool is_imap_running() {
    return IS_IMAP_RUNNING;
}

int stop_imap() {
    IS_IMAP_RUNNING = false;
    return 0;
}