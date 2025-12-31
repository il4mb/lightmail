#ifndef IMPAP_CLIENT_H
#define IMPAP_CLIENT_H

#include "db.h"
#include "imap.h"
#include <stdbool.h>

void handle_list(ClientState *client, const char *tag, const char *args);
void handle_lsub(ClientState *client, const char *tag, const char *args);
void handle_status(ClientState *client, const char *tag, const char *args);
void handle_delete(ClientState *client, const char *tag, const char *mailbox_name);
void handle_append(ClientState *client, const char *tag, const char *args);
void handle_fetch(ClientState *client, const char *tag, const char *args);


void *handle_client(void *arg);

#endif