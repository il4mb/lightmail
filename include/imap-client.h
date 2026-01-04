#ifndef IMPAP_CLIENT_H
#define IMPAP_CLIENT_H

#include "db.h"
#include "imap.h"
#include <stdbool.h>

#define MAX_USERNAME_LEN 255
#define MAX_PASSWORD_LEN 255
#define MAX_MAILBOX_NAME_LEN 255
#define MAX_FLAGS_LEN 512
#define MAX_RESPONSE_LEN 4096
#define MAX_SESSION_ID_LEN 128
#define MAX_ENVELOPE_FIELD_LEN 1024

// void handle_list(ClientState *client, const char *tag, const char *args);
// void handle_lsub(ClientState *client, const char *tag, const char *args);
// void handle_status(ClientState *client, const char *tag, const char *args);
// void handle_delete(ClientState *client, const char *tag, const char *mailbox_name);
static void handle_append(ClientState *client, const char *tag, const char *args);
static void handle_fetch(ClientState *client, const char *tag, const char *args);
static void handle_noop(ClientState *client, const char *tag, const char *args);
static void handle_logout(ClientState *client, const char *tag, const char *args);
static void handle_examine(ClientState *client, const char *tag, const char *args);
static void handle_create(ClientState *client, const char *tag, const char *args);
static void handle_delete(ClientState *client, const char *tag, const char *args);
static void handle_list(ClientState *client, const char *tag, const char *args);
static void handle_lsub(ClientState *client, const char *tag, const char *args);
static void handle_status(ClientState *client, const char *tag, const char *args);
static void handle_check(ClientState *client, const char *tag, const char *args);
static void handle_close(ClientState *client, const char *tag, const char *args);
static void handle_expunge(ClientState *client, const char *tag, const char *args);
static void handle_search(ClientState *client, const char *tag, const char *args);
static void handle_store(ClientState *client, const char *tag, const char *args);
static void handle_copy(ClientState *client, const char *tag, const char *args);
static void handle_uid(ClientState *client, const char *tag, const char *args);

void *handle_client(void *arg);

#endif