
#include <arpa/inet.h>
#include <imap-client.h>
#include <imap-ssl.h>
#include <imap.h>
#include <lightmail.h>
#include <log.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Initialize SSL
SSL_CTX *init_ssl(void) {
    SSL_CTX *ctx;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    const char *cert_path = get_config_value("ssl", "cert_file");
    const char *key_path = get_config_value("ssl", "key_file");

    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0 || SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        printf("Failed to load SSL certificate or key\n");
        LOGE("Failed to load SSL certificate or key\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

// SSL server thread function
void *ssl_server_thread(void *arg) {

    const ImapConfig *cfg = imap_get_config();

    SSL_CTX *ssl_ctx = (SSL_CTX *)arg;
    int ssl_server_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (ssl_server_socket < 0) {
        return NULL;
    }

    struct sockaddr_in ssl_server_addr;
    int opt = 1;
    setsockopt(ssl_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    ssl_server_addr.sin_family = AF_INET;
    ssl_server_addr.sin_addr.s_addr = INADDR_ANY;
    ssl_server_addr.sin_port = htons(cfg->ssl_port);

    if (bind(ssl_server_socket, (struct sockaddr *)&ssl_server_addr, sizeof(ssl_server_addr)) < 0 ||
        listen(ssl_server_socket, cfg->max_clients) < 0) {
        close(ssl_server_socket);
        return NULL;
    }

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        pthread_t thread_id;

        int client_socket = accept(ssl_server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            continue;
        }

        // Create SSL connection
        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        // Create client state
        ClientState *client_state = malloc(sizeof(ClientState));
        if (!client_state) {
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        client_state->socket = client_socket;
        client_state->ssl = ssl;
        client_state->use_ssl = 1;
        inet_ntop(AF_INET, &client_addr.sin_addr, client_state->client_ip, INET6_ADDRSTRLEN);
        client_state->client_port = ntohs(client_addr.sin_port);

        printf("New SSL connection from %s:%d\n",
               client_state->client_ip, client_state->client_port);

        // Create thread for client
        if (pthread_create(&thread_id, NULL, handle_client, client_state) != 0) {
            free(client_state);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        pthread_detach(thread_id);
    }

    close(ssl_server_socket);
    return NULL;
}