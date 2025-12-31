#include "imap.h"
#include <ctype.h>

// Response functions
void send_response(ClientState *client, const char *response) {
    if (client->use_ssl && client->ssl) {
        SSL_write(client->ssl, response, strlen(response));
    } else {
        send(client->socket, response, strlen(response), 0);
    }
}

void send_untagged(ClientState *client, const char *message) {
    char response[MAX_RESPONSE_LENGTH];
    snprintf(response, sizeof(response), "* %s\r\n", message);
    send_response(client, response);
}

void send_tagged_ok(ClientState *client, const char *tag, const char *message) {
    char response[MAX_RESPONSE_LENGTH];
    snprintf(response, sizeof(response), "%s OK %s\r\n", tag, message);
    send_response(client, response);
}

void send_tagged_no(ClientState *client, const char *tag, const char *message) {
    char response[MAX_RESPONSE_LENGTH];
    snprintf(response, sizeof(response), "%s NO %s\r\n", tag, message);
    send_response(client, response);
}

void send_tagged_bad(ClientState *client, const char *tag, const char *message) {
    char response[MAX_RESPONSE_LENGTH];
    snprintf(response, sizeof(response), "%s BAD %s\r\n", tag, message);
    send_response(client, response);
}

/* Send raw bytes to client (useful for streaming binary/message content) */
void send_bytes(ClientState *client, const void *data, size_t len) {
    if (client->use_ssl && client->ssl) {
        SSL_write(client->ssl, data, len);
    } else {
        send(client->socket, data, len, 0);
    }
}

// Parse IMAP command
int parse_command(char *buffer, char *tag, char *command, char *args) {
    char *ptr = buffer;
    int i = 0;

    // Extract tag
    while (*ptr && *ptr != ' ' && i < MAX_TAG_LENGTH - 1) {
        tag[i++] = *ptr++;
    }
    tag[i] = '\0';

    if (!*ptr)
        return 0;
    ptr++; // Skip space

    // Extract command
    i = 0;
    while (*ptr && *ptr != ' ' && i < MAX_COMMAND_LENGTH - 1) {
        command[i++] = toupper(*ptr++);
    }
    command[i] = '\0';

    if (!*ptr) {
        args[0] = '\0';
        return 1;
    }

    ptr++; // Skip space
    size_t arglen = strlen(ptr);
    if (arglen > MAX_BUFFER_SIZE - 1) arglen = MAX_BUFFER_SIZE - 1;
    memcpy(args, ptr, arglen);
    args[arglen] = '\0';

    return 1;
}
