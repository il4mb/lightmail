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
imap_parse_result parse_imap_command(const char *buffer, char *tag, char *command, char *args) {
    if (!buffer || *buffer == '\0')
        return IMAP_PARSE_ERROR_EMPTY;

    const char *ptr = buffer;

    // 1. Skip leading whitespace
    while (isspace((unsigned char)*ptr))
        ptr++;

    // 2. Extract Tag
    int i = 0;
    while (*ptr && !isspace((unsigned char)*ptr) && i < MAX_TAG_LENGTH - 1) {
        tag[i++] = *ptr++;
    }
    tag[i] = '\0';

    if (i == 0)
        return IMAP_PARSE_ERROR_INVALID_TAG;
    while (isspace((unsigned char)*ptr))
        ptr++; // Move to start of command

    // 3. Extract Command
    i = 0;
    while (*ptr && !isspace((unsigned char)*ptr) && i < MAX_COMMAND_LENGTH - 1) {
        command[i++] = (char)toupper((unsigned char)*ptr++);
    }
    command[i] = '\0';

    if (i == 0)
        return IMAP_PARSE_ERROR_INVALID_COMMAND;

    // 4. Extract Arguments
    while (isspace((unsigned char)*ptr))
        ptr++; // Move to start of args

    // Copy remaining buffer as args, stripping trailing CRLF/whitespace
    if (*ptr) {
        strncpy(args, ptr, MAX_BUFFER_SIZE - 1);
        args[MAX_BUFFER_SIZE - 1] = '\0';

        // Trim trailing \r \n and spaces
        char *end = args + strlen(args) - 1;
        while (end >= args && isspace((unsigned char)*end)) {
            *end-- = '\0';
        }
    } else {
        args[0] = '\0';
    }

    return IMAP_PARSE_SUCCESS;
}