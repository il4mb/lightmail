#ifndef LMTP_SESSION_H
#define LMTP_SESSION_H

#include <sys/types.h>

// Represents the state of an LMTP session.
typedef enum {
    LMTP_STATE_GREETING,
    LMTP_STATE_LHLO,
    LMTP_STATE_MAIL,
    LMTP_STATE_RCPT,
    LMTP_STATE_DATA,
    LMTP_STATE_QUIT
} lmtp_state;

// Structure to hold all information about a single LMTP client session.
typedef struct lmtp_session {
    int client_fd;
    lmtp_state state;
    char client_hostname[256];
    char* mail_from;
    // A dynamic array of recipient addresses
    char** rcpt_to;
    size_t rcpt_count;
    size_t rcpt_capacity;
} lmtp_session_t;

/**
 * @brief Handles a single LMTP client session.
 *
 * This function is responsible for the entire lifecycle of an LMTP session,
 * from reading commands to processing the DATA content and sending responses.
 *
 * @param client_fd The file descriptor for the connected client socket.
 */
void handle_lmtp_session(int client_fd);

#endif // LMTP_SESSION_H
