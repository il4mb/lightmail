#include "imap.h"
#include "db.h"
#include "imap-client.h"
#include "imap-ssl.h"
#include "log.h"
#include "mailbox.h"
#include "s3.h"
#include "shutdown.h"
#include "metrics.h"

#include <arpa/inet.h>
#include <conf.h>
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

// #define MAX_TAG_LENGTH 64 // 64 bytes
// #define MAX_COMMAND_LENGTH 64 // 64 bytes
// #define MAX_RESPONSE_LENGTH 4096 // 4KB
// #define SESSION_TIMEOUT 1800 // 30 minutes

void imap_config_callback(const char *key, const char *value, void *ctx) {
    ImapConfig *cfg = (ImapConfig *)ctx;

    if (strcmp(key, "port") == 0) {
        cfg->port = atoi(value);
    } else if (strcmp(key, "ssl_port") == 0) {
        cfg->ssl_port = atoi(value);
    } else if (strcmp(key, "max_clients") == 0) {
        cfg->max_clients = atoi(value);
    } else if (strcmp(key, "timeout") == 0) {
        cfg->timeout = atoi(value);
    } else if (strcmp(key, "buffer_size") == 0) {
        cfg->buffer_size = atoi(value);
    } else if (strcmp(key, "max_message_size") == 0) {
        cfg->max_message_size = (size_t)atoll(value);
    }
}

ImapConfig cfg = {
    .port = 143,
    .ssl_port = 993,
    .max_clients = 100,
    .timeout = 300,
    .buffer_size = 8192,
    .max_message_size = 10 * 1024 * 1024 /* 10MB default */};

ImapConfig *get_config_imap() {
    return &cfg;
}

bool IS_IMAP_RUNNING = false;

/* Track current client count and enforce max_clients */
static int current_clients = 0;
static pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;

int imap_increment_client(void) {
    pthread_mutex_lock(&clients_lock);
    if (current_clients >= cfg.max_clients) {
        pthread_mutex_unlock(&clients_lock);
        return 0;
    }
    current_clients++;
    pthread_mutex_unlock(&clients_lock);

    /* Metrics: increment IMAP sessions */
    metrics_inc_imap_sessions();

    return 1;
}

void imap_decrement_client(void) {
    pthread_mutex_lock(&clients_lock);
    if (current_clients > 0) current_clients--;
    pthread_mutex_unlock(&clients_lock);

    /* Metrics: decrement IMAP sessions */
    metrics_dec_imap_sessions();
}

/* Helper context passed to the IMAP server thread */
typedef struct {
    int server_socket;
    int ssl_server_socket;
    SSL_CTX *ssl_ctx;
} ImapServerContext;

static void *imap_server_loop(void *arg) {
    ImapServerContext *ctx = (ImapServerContext *)arg;
    int server_socket = ctx->server_socket;
    int ssl_server_socket = ctx->ssl_server_socket;
    SSL_CTX *ssl_ctx = ctx->ssl_ctx;

    pthread_t thread_id;

    IS_IMAP_RUNNING = true;

    /* client_addr is used per-connection below */
    LOGI("IMAP server loop started");

    while (1) {
        struct sockaddr_in client_addr_local;
        socklen_t client_len_local = sizeof(client_addr_local);

        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr_local, &client_len_local);
        if (client_socket < 0) {
            perror("Accept failed");
            LOGE("Failed to accept connection");
            continue;
        }

        // Create client state
        ClientState *client_state = malloc(sizeof(ClientState));
        if (!client_state) {
            close(client_socket);
            continue;
        }

        client_state->socket = client_socket;
        client_state->ssl = NULL;
        client_state->use_ssl = 0;
        inet_ntop(AF_INET, &client_addr_local.sin_addr, client_state->client_ip, INET6_ADDRSTRLEN);
        client_state->client_port = ntohs(client_addr_local.sin_port);

        printf("New connection from %s:%d\n", client_state->client_ip, client_state->client_port);
        LOGI("New connection from %s:%d", client_state->client_ip, client_state->client_port);

        // Enforce max clients
        if (!imap_increment_client()) {
            LOGW("Rejecting connection from %s:%d: server busy", client_state->client_ip, client_state->client_port);
            free(client_state);
            close(client_socket);
            continue;
        }

        // Create thread for client
        if (pthread_create(&thread_id, NULL, handle_client, client_state) != 0) {
            close(client_socket);
            imap_decrement_client();
            free(client_state);
            continue;
        }
        pthread_detach(thread_id);
    }

    /* cleanup */
    if (server_socket >= 0) close(server_socket);
    if (ssl_server_socket >= 0) close(ssl_server_socket);
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    free(ctx);

    LOGI("IMAP server loop stopped");
    IS_IMAP_RUNNING = false;
    return NULL;
}

int start_imap() {

    get_config_section("imap", imap_config_callback, &cfg);

    int server_socket = -1, ssl_server_socket = -1;
    struct sockaddr_in server_addr, ssl_server_addr;
    pthread_t thread_id;
    SSL_CTX *ssl_ctx = NULL;

    int port_available = is_port_available(cfg.port);
    int port_ssl_available = is_port_available(cfg.ssl_port);

    if (port_available == 0) {
        LOGE("Port %d is already in use. IMAP server cannot start.", cfg.port);
        fprintf(stderr, "Error: Port %d is already in use. IMAP server cannot start.\n", cfg.port);
        close(server_socket);
        if (ssl_ctx) {
            SSL_CTX_free(ssl_ctx);
        }
        return 1;
    }
    if (port_available == -1) {
        LOGE("Error checking port %d availability", cfg.port);
        fprintf(stderr, "Error: Error checking port %d availability\n", cfg.port);
        close(server_socket);
        if (ssl_ctx) {
            SSL_CTX_free(ssl_ctx);
        }
        return 1;
    }
    if (port_ssl_available == 0) {
        LOGE("Port %d is already in use. IMAPS server cannot start.", cfg.ssl_port);
        fprintf(stderr, "Error: Port %d is already in use. IMAPS server cannot start.\n", cfg.ssl_port);
        close(server_socket);
        if (ssl_ctx) {
            SSL_CTX_free(ssl_ctx);
        }
        return 1;
    }
    if (port_ssl_available == -1) {
        LOGE("Error checking port %d availability", cfg.ssl_port);
        fprintf(stderr, "Error: Error checking port %d availability\n", cfg.ssl_port);
        close(server_socket);
        if (ssl_ctx) {
            SSL_CTX_free(ssl_ctx);
        }
        return 1;
    }

    // Initialize SSL for IMAPS
    ssl_ctx = init_ssl();
    if (!ssl_ctx) {
        LOGE("SSL initialization failed, IMAPS will not be available");
        fprintf(stderr, "Warning: SSL initialization failed, IMAPS will not be available\n");
    }

    // Create regular IMAP socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        LOGE("Failed to create socket");
        return 1;
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        LOGE("Failed to set socket options");
        close(server_socket);
        return 1;
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(cfg.port);

    // Bind socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        LOGE("Failed to bind socket");
        perror("Bind failed");
        return 1;
    }

    // Listen for connections
    if (listen(server_socket, cfg.max_clients) < 0) {
        LOGE("Failed to listen on socket");
        perror("Listen failed");
        return 1;
    }

    LOGI("IMAP server started on port %d", cfg.port);
    printf("IMAP server listening on port %d\n", cfg.port);

    // Create SSL IMAP socket if SSL is available
    if (ssl_ctx) {
        ssl_server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (ssl_server_socket >= 0) {
            setsockopt(ssl_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

            ssl_server_addr.sin_family = AF_INET;
            ssl_server_addr.sin_addr.s_addr = INADDR_ANY;
            ssl_server_addr.sin_port = htons(cfg.ssl_port);

            if (bind(ssl_server_socket, (struct sockaddr *)&ssl_server_addr, sizeof(ssl_server_addr)) >= 0 &&
                listen(ssl_server_socket, cfg.max_clients) >= 0) {
                printf("IMAPS server listening on port %d\n", cfg.ssl_port);

                // Create thread for SSL server
                pthread_create(&thread_id, NULL, ssl_server_thread, (void *)ssl_ctx);
                pthread_detach(thread_id);
            } else {
                close(ssl_server_socket);
                ssl_server_socket = -1;
            }
        }
    }

    /* spawn background accept loop so start_imap can return success to the caller */
    ImapServerContext *ctx = malloc(sizeof(ImapServerContext));
    if (!ctx) {
        if (server_socket >= 0) close(server_socket);
        if (ssl_server_socket >= 0) close(ssl_server_socket);
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
        return 1;
    }
    ctx->server_socket = server_socket;
    ctx->ssl_server_socket = ssl_server_socket;
    ctx->ssl_ctx = ssl_ctx;

    if (pthread_create(&thread_id, NULL, imap_server_loop, ctx) != 0) {
        if (server_socket >= 0) close(server_socket);
        if (ssl_server_socket >= 0) close(ssl_server_socket);
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
        free(ctx);
        return 1;
    }
    pthread_detach(thread_id);

    return 0;
}

bool is_imap_running() {
    return IS_IMAP_RUNNING;
}