
#ifndef SERVER_H
#define SERVER_H

#include "db.h"
#include <netinet/in.h>
#include <stdbool.h>
#include <openssl/ssl.h>

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

int stop_imap();
// Start IMAP server
int start_imap();

bool is_imap_running();

#endif