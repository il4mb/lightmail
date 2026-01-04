
#ifndef SERVER_H
#define SERVER_H

#include "db.h"
#include <netinet/in.h>
#include <stdbool.h>
#include <openssl/ssl.h>

#define MAX_ENVELOPE_FIELD_LEN 1024
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
    size_t max_message_size; 
} ImapConfig;

// IMAP session state
typedef struct {
    int socket;
    SSL *ssl;
    int use_ssl;
    int authenticated;
    int welcome_sent;
    int bad_count;
    Account *account;
    Mailbox *current_mailbox;
    char current_mailbox_name[256];
    char session_id[128];
    time_t last_activity;
    char client_ip[INET6_ADDRSTRLEN];
    int client_port;
} ClientState;

ImapConfig *imap_get_config();
int imap_init();
int imap_start();
void imap_stop();
int imap_increment_client(void);
void imap_decrement_client(void);

void send_response(ClientState *client, const char *response);
int parse_command(char *buffer, char *tag, char *command, char *args);
void send_untagged(ClientState *client, const char *message);
void send_tagged_ok(ClientState *client, const char *tag, const char *message);
void send_tagged_no(ClientState *client, const char *tag, const char *message);
void send_tagged_bad(ClientState *client, const char *tag, const char *message);
void send_bytes(ClientState *client, const void *data, size_t len);

#endif