#include "imap.h"

// Response functions
void send_response(ClientState *client, const char *response) {
    if (client->use_ssl && client->ssl) {
        SSL_write(client->ssl, response, strlen(response));
    } else {
        send(client->socket, response, strlen(response), 0);
    }
}