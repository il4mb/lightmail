
#ifndef SERVER_H
#define SERVER_H

#include "db.h"
#include <netinet/in.h>
#include <stdbool.h>
#include <openssl/ssl.h>

#define MAX_BUFFER_SIZE 8192
#define MAX_TAG_LENGTH 64
#define MAX_COMMAND_LENGTH 64
#define MAX_RESPONSE_LENGTH 4096
#define SESSION_TIMEOUT 1800

typedef struct {
    int port;
    int ssl_port;
    int max_clients;
    int timeout;
    int buffer_size;
} ImapConfig;

// IMAP session state
typedef struct {
    int socket;
    SSL *ssl;
    int use_ssl;
    int authenticated;
    Account *account;
    Mailbox *current_mailbox;
    char current_mailbox_name[256];
    char session_id[128];
    time_t last_activity;
    char client_ip[INET6_ADDRSTRLEN];
    int client_port;
} ClientState;

static ImapConfig *get_config_imap();
int start_imap();
bool is_imap_running();

void send_response(ClientState *client, const char *response);
void send_untagged(ClientState *client, const char *message);
void send_tagged_ok(ClientState *client, const char *tag, const char *message);
void send_tagged_no(ClientState *client, const char *tag, const char *message);
void send_tagged_bad(ClientState *client, const char *tag, const char *message);

#endif