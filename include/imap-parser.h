#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define MAX_TAG_LENGTH 32
#define MAX_COMMAND_LENGTH 16
#define MAX_BUFFER_SIZE 1024

typedef enum {
    IMAP_PARSE_SUCCESS = 0,
    IMAP_PARSE_ERROR_EMPTY,
    IMAP_PARSE_ERROR_INVALID_TAG,
    IMAP_PARSE_ERROR_INVALID_COMMAND,
    IMAP_PARSE_ERROR_BUFFER_OVERFLOW
} imap_parse_result;


/**
 * Robustly parses an IMAP command string.
 * Handles CRLF, leading/trailing whitespace, and length constraints.
 */
imap_parse_result parse_imap_command(const char *buffer, char *tag, char *command, char *args);


/**
 * 
 */
void parse_message_headers(const char *headers, Message *msg);