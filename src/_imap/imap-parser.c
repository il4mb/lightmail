#include <imap-client.h>
#include <imap-parser.h>
#include <imap.h>

size_t safe_strncpy(char *dest, const char *src, size_t dest_size) {
    if (!dest || dest_size == 0) {
        return 0;
    }

    if (!src) {
        dest[0] = '\0';
        return 0;
    }

    size_t i = 0;

    // Copy up to dest_size - 1 characters
    while (i < dest_size - 1 && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }

    // Always null-terminate
    dest[i] = '\0';

    return i;
}

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

void parse_message_headers(const char *headers, Message *msg) {
    if (!headers || !msg)
        return;

    const char *ptr = headers;

    // Parse From header
    const char *from_start = strstr(ptr, "\nFrom:");
    if (!from_start)
        from_start = strstr(ptr, "\r\nFrom:");
    if (from_start) {
        from_start += 6; // Skip "From:"
        while (*from_start && isspace(*from_start))
            from_start++;

        const char *from_end = strchr(from_start, '\n');
        if (!from_end)
            from_end = strchr(from_start, '\r');
        if (from_end) {
            size_t len = (size_t)(from_end - from_start);
            if (len > MAX_ENVELOPE_FIELD_LEN)
                len = MAX_ENVELOPE_FIELD_LEN;

            free(msg->envelope_from);
            msg->envelope_from = malloc(len + 1);
            if (msg->envelope_from) {
                safe_strncpy(msg->envelope_from, from_start, len + 1);
            }
        }
    }

    // Parse Subject header
    const char *subject_start = strstr(ptr, "\nSubject:");
    if (!subject_start)
        subject_start = strstr(ptr, "\r\nSubject:");
    if (subject_start) {
        subject_start += 8; // Skip "Subject:"
        while (*subject_start && isspace(*subject_start))
            subject_start++;

        const char *subject_end = strchr(subject_start, '\n');
        if (!subject_end)
            subject_end = strchr(subject_start, '\r');
        if (subject_end) {
            size_t len = (size_t)(subject_end - subject_start);
            if (len > MAX_ENVELOPE_FIELD_LEN)
                len = MAX_ENVELOPE_FIELD_LEN;

            free(msg->envelope_subject);
            msg->envelope_subject = malloc(len + 1);
            if (msg->envelope_subject) {
                safe_strncpy(msg->envelope_subject, subject_start, len + 1);
            }
        }
    }
}