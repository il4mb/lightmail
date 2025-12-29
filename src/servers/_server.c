#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "db.h"
#include "s3.h"
#include "mailbox.h"
#include "../config/config.h"

#define MAX_BUFFER_SIZE 8192
#define MAX_TAG_LENGTH 64
#define MAX_COMMAND_LENGTH 64
#define MAX_RESPONSE_LENGTH 4096
#define SESSION_TIMEOUT 1800

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

// Parse IMAP command
int parse_command(char *buffer, char *tag, char *command, char *args) {
    char *ptr = buffer;
    int i = 0;
    
    // Extract tag
    while (*ptr && *ptr != ' ' && i < MAX_TAG_LENGTH - 1) {
        tag[i++] = *ptr++;
    }
    tag[i] = '\0';
    
    if (!*ptr) return 0;
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
    strncpy(args, ptr, MAX_BUFFER_SIZE - (ptr - buffer) - 1);
    args[MAX_BUFFER_SIZE - (ptr - buffer) - 1] = '\0';
    
    return 1;
}

// Validate session timeout
int check_session_timeout(ClientState *client) {
    time_t now = time(NULL);
    if (now - client->last_activity > SESSION_TIMEOUT) {
        send_untagged(client, "BYE Session timeout");
        return 0;
    }
    client->last_activity = now;
    return 1;
}

// Handle CAPABILITY command
void handle_capability(ClientState *client, const char *tag) {
    send_untagged(client, "CAPABILITY IMAP4rev1 AUTH=PLAIN STARTTLS");
    if (client->use_ssl) {
        send_untagged(client, "LOGINDISABLED");
    }
    send_untagged(client, "UIDPLUS");
    send_untagged(client, "UNSELECT");
    send_untagged(client, "IDLE");
    send_untagged(client, "NAMESPACE");
    send_untagged(client, "QUOTA");
    send_untagged(client, "ACL");
    send_untagged(client, "RIGHTS=kxte");
    send_untagged(client, "ESEARCH");
    send_untagged(client, "SORT");
    send_untagged(client, "THREAD=ORDEREDSUBJECT");
    send_untagged(client, "THREAD=REFERENCES");
    send_untagged(client, "MULTIAPPEND");
    send_untagged(client, "URL-PARTIAL");
    send_untagged(client, "CATENATE");
    send_untagged(client, "CONDSTORE");
    send_tagged_ok(client, tag, "CAPABILITY completed");
}

// Handle NOOP command
void handle_noop(ClientState *client, const char *tag) {
    check_session_timeout(client);
    send_tagged_ok(client, tag, "NOOP completed");
}

// Handle LOGIN command
void handle_login(ClientState *client, const char *tag, const char *args) {
    if (client->use_ssl && !client->ssl) {
        send_tagged_no(client, tag, "LOGIN disabled, use STARTTLS first");
        return;
    }
    
    char username[256];
    char password[256];
    
    // Parse username and password (they might be quoted)
    if (args[0] == '"') {
        const char *end = strchr(args + 1, '"');
        if (!end) {
            send_tagged_bad(client, tag, "Invalid arguments");
            return;
        }
        int len = end - (args + 1);
        strncpy(username, args + 1, len);
        username[len] = '\0';
        
        // Find password (skip spaces after closing quote)
        args = end + 1;
        while (*args && isspace(*args)) args++;
        
        if (args[0] == '"') {
            end = strchr(args + 1, '"');
            if (!end) {
                send_tagged_bad(client, tag, "Invalid arguments");
                return;
            }
            len = end - (args + 1);
            strncpy(password, args + 1, len);
            password[len] = '\0';
        } else {
            sscanf(args, "%255s", password);
        }
    } else {
        if (sscanf(args, "%255s %255s", username, password) != 2) {
            send_tagged_bad(client, tag, "Invalid arguments");
            return;
        }
    }
    
    // Extract domain from username (format: user@domain or just user)
    char *domain = "example.com"; // Default domain
    char user_only[256];
    strncpy(user_only, username, sizeof(user_only));
    
    char *at_sign = strchr(user_only, '@');
    if (at_sign) {
        *at_sign = '\0';
        domain = at_sign + 1;
    }
    
    // Get account from database
    Account *account = db_get_account_by_username(user_only, domain);
    if (!account) {
        send_tagged_no(client, tag, "LOGIN failed");
        return;
    }
    
    // Verify password
    if (!db_verify_password(account, password)) {
        free(account->username);
        free(account->email);
        if (account->full_name) free(account->full_name);
        free(account);
        send_tagged_no(client, tag, "LOGIN failed");
        return;
    }
    
    // Update client state
    client->authenticated = 1;
    client->account = account;
    client->last_activity = time(NULL);
    
    // Generate session ID
    snprintf(client->session_id, sizeof(client->session_id),
            "%s-%s-%ld", user_only, domain, time(NULL));
    
    send_tagged_ok(client, tag, "LOGIN completed");
}

// Handle SELECT command
void handle_select(ClientState *client, const char *tag, const char *mailbox_name) {
    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }
    
    if (!check_session_timeout(client)) {
        return;
    }
    
    // Clean previous mailbox
    if (client->current_mailbox) {
        free(client->current_mailbox->name);
        free(client->current_mailbox->flags);
        free(client->current_mailbox->permanent_flags);
        free(client->current_mailbox);
        client->current_mailbox = NULL;
    }
    
    // Get mailbox from database
    Mailbox *mailbox = db_get_mailbox(client->account->id, mailbox_name);
    if (!mailbox) {
        send_tagged_no(client, tag, "Mailbox not found");
        return;
    }
    
    // Update client state
    client->current_mailbox = mailbox;
    strncpy(client->current_mailbox_name, mailbox_name, sizeof(client->current_mailbox_name) - 1);
    
    // Send mailbox status
    char response[MAX_RESPONSE_LENGTH];
    
    // Send flags
    snprintf(response, sizeof(response), "FLAGS (%s)", mailbox->flags);
    send_untagged(client, response);
    
    // Send permanent flags
    snprintf(response, sizeof(response), "OK [PERMANENTFLAGS (%s)] Flags permitted.", mailbox->permanent_flags);
    send_untagged(client, response);
    
    // Send message counts
    snprintf(response, sizeof(response), "%d EXISTS", mailbox->total_messages);
    send_untagged(client, response);
    
    snprintf(response, sizeof(response), "%d RECENT", mailbox->recent_messages);
    send_untagged(client, response);
    
    // Ensure INBOX has unseen count
    if (strcasecmp(mailbox_name, "INBOX") == 0 && mailbox->unseen_messages < 0) {
        mailbox->unseen_messages = 0;
    }
    
    // Send UID information
    snprintf(response, sizeof(response), 
             "OK [UIDVALIDITY %d] UIDs valid", mailbox->uid_validity);
    send_untagged(client, response);
    
    snprintf(response, sizeof(response), 
             "OK [UIDNEXT %d] Predicted next UID", mailbox->uid_next);
    send_untagged(client, response);
    
    // Send unseen count if available
    if (mailbox->unseen_messages >= 0) {
        snprintf(response, sizeof(response),
                 "OK [UNSEEN %d] First unseen message", mailbox->unseen_messages + 1);
        send_untagged(client, response);
    }
    
    send_tagged_ok(client, tag, "[READ-WRITE] SELECT completed");
}

// Handle EXAMINE command (read-only SELECT)
void handle_examine(ClientState *client, const char *tag, const char *mailbox_name) {
    handle_select(client, tag, mailbox_name);
    // In a full implementation, we would mark the mailbox as read-only
}

// Handle CREATE command
void handle_create(ClientState *client, const char *tag, const char *mailbox_name) {
    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }
    
    if (!check_session_timeout(client)) {
        return;
    }
    
    // Check if mailbox already exists
    Mailbox *existing = db_get_mailbox(client->account->id, mailbox_name);
    if (existing) {
        free(existing->name);
        free(existing->flags);
        free(existing->permanent_flags);
        free(existing);
        send_tagged_no(client, tag, "Mailbox already exists");
        return;
    }
    
    // Create mailbox in database
    if (db_create_mailbox(client->account->id, mailbox_name, "\\Answered \\Flagged \\Deleted \\Seen \\Draft")) {
        send_tagged_ok(client, tag, "CREATE completed");
    } else {
        send_tagged_no(client, tag, "CREATE failed");
    }
}

// Handle DELETE command
void handle_delete(ClientState *client, const char *tag, const char *mailbox_name) {
    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }
    
    if (!check_session_timeout(client)) {
        return;
    }
    
    // Can't delete INBOX
    if (strcasecmp(mailbox_name, "INBOX") == 0) {
        send_tagged_no(client, tag, "Cannot delete INBOX");
        return;
    }
    
    // Get mailbox
    Mailbox *mailbox = db_get_mailbox(client->account->id, mailbox_name);
    if (!mailbox) {
        send_tagged_no(client, tag, "Mailbox not found");
        return;
    }
    
    // Check if mailbox is selected
    if (client->current_mailbox && client->current_mailbox->id == mailbox->id) {
        free(mailbox->name);
        free(mailbox->flags);
        free(mailbox->permanent_flags);
        free(mailbox);
        send_tagged_no(client, tag, "Cannot delete selected mailbox");
        return;
    }
    
    // Delete mailbox from database
    if (db_delete_mailbox(mailbox->id)) {
        send_tagged_ok(client, tag, "DELETE completed");
    } else {
        send_tagged_no(client, tag, "DELETE failed");
    }
    
    free(mailbox->name);
    free(mailbox->flags);
    free(mailbox->permanent_flags);
    free(mailbox);
}

// Handle LIST command
void handle_list(ClientState *client, const char *tag, const char *args) {
    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }
    
    if (!check_session_timeout(client)) {
        return;
    }
    
    // Parse reference and mailbox pattern
    char reference[256];
    char pattern[256];
    
    if (sscanf(args, "\"%255[^\"]\" \"%255[^\"]\"", reference, pattern) != 2 &&
        sscanf(args, "%255s %255s", reference, pattern) != 2) {
        send_tagged_bad(client, tag, "Invalid arguments");
        return;
    }
    
    // Get mailboxes from database
    int count;
    Mailbox **mailboxes = db_get_mailboxes(client->account->id, &count);
    
    if (!mailboxes) {
        send_tagged_ok(client, tag, "LIST completed");
        return;
    }
    
    // Send mailbox list
    for (int i = 0; i < count; i++) {
        // Check if mailbox matches pattern
        // Simple pattern matching (supports * and % wildcards)
        int match = 1;
        if (strcmp(pattern, "*") != 0) {
            // Basic pattern matching implementation
            // In production, use proper IMAP pattern matching
            if (strstr(mailboxes[i]->name, pattern) == NULL &&
                strcmp(pattern, "%") != 0) {
                match = 0;
            }
        }
        
        if (match) {
            char response[MAX_RESPONSE_LENGTH];
            snprintf(response, sizeof(response),
                    "LIST (\\HasNoChildren) \"/\" \"%s\"",
                    mailboxes[i]->name);
            send_untagged(client, response);
        }
        
        free(mailboxes[i]->name);
        free(mailboxes[i]);
    }
    free(mailboxes);
    
    send_tagged_ok(client, tag, "LIST completed");
}

// Handle LSUB command (subscribed mailboxes)
void handle_lsub(ClientState *client, const char *tag, const char *args) {
    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }
    
    if (!check_session_timeout(client)) {
        return;
    }
    
    // Similar to LIST but only shows subscribed mailboxes
    // For simplicity, we'll show all mailboxes
    handle_list(client, tag, args);
}

// Handle STATUS command
void handle_status(ClientState *client, const char *tag, const char *args) {
    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }
    
    if (!check_session_timeout(client)) {
        return;
    }
    
    char mailbox_name[256];
    char status_items[256];
    
    if (sscanf(args, "\"%255[^\"]\" (%255[^)])", mailbox_name, status_items) != 2 &&
        sscanf(args, "%255s (%255[^)])", mailbox_name, status_items) != 2) {
        send_tagged_bad(client, tag, "Invalid arguments");
        return;
    }
    
    // Get mailbox from database
    Mailbox *mailbox = db_get_mailbox(client->account->id, mailbox_name);
    if (!mailbox) {
        send_tagged_no(client, tag, "Mailbox not found");
        return;
    }
    
    // Parse requested status items
    char *item = strtok(status_items, " ");
    char response[MAX_RESPONSE_LENGTH];
    snprintf(response, sizeof(response), "STATUS \"%s\" (", mailbox_name);
    char temp[256];
    
    int first = 1;
    while (item) {
        if (!first) {
            strcat(response, " ");
        }
        first = 0;
        
        if (strcasecmp(item, "MESSAGES") == 0) {
            snprintf(temp, sizeof(temp), "MESSAGES %d", mailbox->total_messages);
            strcat(response, temp);
        } else if (strcasecmp(item, "RECENT") == 0) {
            snprintf(temp, sizeof(temp), "RECENT %d", mailbox->recent_messages);
            strcat(response, temp);
        } else if (strcasecmp(item, "UIDNEXT") == 0) {
            snprintf(temp, sizeof(temp), "UIDNEXT %d", mailbox->uid_next);
            strcat(response, temp);
        } else if (strcasecmp(item, "UIDVALIDITY") == 0) {
            snprintf(temp, sizeof(temp), "UIDVALIDITY %d", mailbox->uid_validity);
            strcat(response, temp);
        } else if (strcasecmp(item, "UNSEEN") == 0 && mailbox->unseen_messages >= 0) {
            snprintf(temp, sizeof(temp), "UNSEEN %d", mailbox->unseen_messages);
            strcat(response, temp);
        }
        
        item = strtok(NULL, " ");
    }
    
    strcat(response, ")");
    send_untagged(client, response);
    
    free(mailbox->name);
    free(mailbox->flags);
    free(mailbox->permanent_flags);
    free(mailbox);
    
    send_tagged_ok(client, tag, "STATUS completed");
}

// Handle APPEND command
void handle_append(ClientState *client, const char *tag, const char *args) {
    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }
    
    if (!check_session_timeout(client)) {
        return;
    }
    
    char mailbox_name[256];
    char flags[256] = "";
    char date_time[64] = "";
    size_t message_size = 0;
    
    // Parse arguments
    const char *ptr = args;
    
    // Parse mailbox name
    if (*ptr == '"') {
        ptr++;
        const char *end = strchr(ptr, '"');
        if (!end) {
            send_tagged_bad(client, tag, "Invalid arguments");
            return;
        }
        int len = end - ptr;
        strncpy(mailbox_name, ptr, len);
        mailbox_name[len] = '\0';
        ptr = end + 1;
    } else {
        int len = 0;
        while (*ptr && *ptr != ' ' && len < 255) {
            mailbox_name[len++] = *ptr++;
        }
        mailbox_name[len] = '\0';
    }
    
    // Skip spaces
    while (*ptr && isspace(*ptr)) ptr++;
    
    // Parse optional flags
    if (*ptr == '(') {
        ptr++;
        const char *end = strchr(ptr, ')');
        if (!end) {
            send_tagged_bad(client, tag, "Invalid arguments");
            return;
        }
        int len = end - ptr;
        strncpy(flags, ptr, len);
        flags[len] = '\0';
        ptr = end + 1;
        
        // Skip spaces
        while (*ptr && isspace(*ptr)) ptr++;
    }
    
    // Parse optional date-time
    if (*ptr == '"') {
        ptr++;
        const char *end = strchr(ptr, '"');
        if (!end) {
            send_tagged_bad(client, tag, "Invalid arguments");
            return;
        }
        int len = end - ptr;
        strncpy(date_time, ptr, len);
        date_time[len] = '\0';
        ptr = end + 1;
        
        // Skip spaces
        while (*ptr && isspace(*ptr)) ptr++;
    }
    
    // Parse message size
    if (*ptr == '{') {
        ptr++;
        message_size = strtoul(ptr, NULL, 10);
        
        // Find closing brace and skip to literal start
        ptr = strchr(ptr, '}');
        if (!ptr) {
            send_tagged_bad(client, tag, "Invalid arguments");
            return;
        }
        ptr++;
        
        // Skip \r\n after literal size
        while (*ptr && isspace(*ptr)) ptr++;
    } else {
        send_tagged_bad(client, tag, "Message size required");
        return;
    }
    
    // Get mailbox
    Mailbox *mailbox = db_get_mailbox(client->account->id, mailbox_name);
    if (!mailbox) {
        send_tagged_no(client, tag, "Mailbox not found");
        return;
    }
    
    // Send continuation response for literal data
    send_response(client, "+ Ready for literal data\r\n");
    
    // Read message data
    char *message_data = malloc(message_size + 1);
    if (!message_data) {
        free(mailbox->name);
        free(mailbox->flags);
        free(mailbox->permanent_flags);
        free(mailbox);
        send_tagged_no(client, tag, "Server error");
        return;
    }
    
    size_t bytes_read = 0;
    while (bytes_read < message_size) {
        ssize_t n;
        if (client->use_ssl && client->ssl) {
            n = SSL_read(client->ssl, message_data + bytes_read, message_size - bytes_read);
        } else {
            n = recv(client->socket, message_data + bytes_read, message_size - bytes_read, 0);
        }
        
        if (n <= 0) {
            free(message_data);
            free(mailbox->name);
            free(mailbox->flags);
            free(mailbox->permanent_flags);
            free(mailbox);
            return;
        }
        bytes_read += n;
    }
    message_data[message_size] = '\0';
    
    // Get next UID
    int next_uid = db_get_next_uid(mailbox->id);
    if (next_uid < 0) {
        free(message_data);
        free(mailbox->name);
        free(mailbox->flags);
        free(mailbox->permanent_flags);
        free(mailbox);
        send_tagged_no(client, tag, "Server error");
        return;
    }
    
    // Upload message to S3
    char *s3_key = s3_upload_message(client->account->id, mailbox->id, next_uid,
                                    message_data, message_size, "message/rfc822");
    
    if (!s3_key) {
        free(message_data);
        free(mailbox->name);
        free(mailbox->flags);
        free(mailbox->permanent_flags);
        free(mailbox);
        send_tagged_no(client, tag, "Failed to store message");
        return;
    }
    
    // Create message record
    Message *message = malloc(sizeof(Message));
    if (!message) {
        free(s3_key);
        free(message_data);
        free(mailbox->name);
        free(mailbox->flags);
        free(mailbox->permanent_flags);
        free(mailbox);
        send_tagged_no(client, tag, "Server error");
        return;
    }
    
    message->mailbox_id = mailbox->id;
    message->uid = next_uid;
    message->internal_date = time(NULL);
    message->flags = strdup(flags);
    message->size = message_size;
    
    // Parse basic envelope info from message
    // In production, implement full MIME parsing
    char *from = strstr(message_data, "\nFrom:");
    char *subject = strstr(message_data, "\nSubject:");
    
    if (from) {
        from += 6; // Skip "From:"
        while (*from && isspace(*from)) from++;
        char *end = strchr(from, '\n');
        if (end) {
            int len = end - from;
            message->envelope_from = malloc(len + 1);
            strncpy(message->envelope_from, from, len);
            message->envelope_from[len] = '\0';
        } else {
            message->envelope_from = strdup("Unknown");
        }
    } else {
        message->envelope_from = strdup("Unknown");
    }
    
    if (subject) {
        subject += 8; // Skip "Subject:"
        while (*subject && isspace(*subject)) subject++;
        char *end = strchr(subject, '\n');
        if (end) {
            int len = end - subject;
            message->envelope_subject = malloc(len + 1);
            strncpy(message->envelope_subject, subject, len);
            message->envelope_subject[len] = '\0';
        } else {
            message->envelope_subject = strdup("");
        }
    } else {
        message->envelope_subject = strdup("");
    }
    
    message->envelope_to = strdup(client->account->email);
    message->body_s3_key = s3_key;
    message->body_size = message_size;
    message->mime_type = strdup("message/rfc822");
    message->encoding = strdup("8bit");
    
    // Store message in database
    if (db_store_message(message)) {
        // Free message resources
        free(message->flags);
        free(message->envelope_from);
        free(message->envelope_to);
        free(message->envelope_subject);
        free(message->body_s3_key);
        free(message->mime_type);
        free(message->encoding);
        free(message);
        
        free(message_data);
        free(mailbox->name);
        free(mailbox->flags);
        free(mailbox->permanent_flags);
        free(mailbox);
        
        send_tagged_ok(client, tag, "APPEND completed");
    } else {
        // Cleanup on failure
        s3_delete_message(s3_key);
        
        free(message->flags);
        free(message->envelope_from);
        free(message->envelope_to);
        free(message->envelope_subject);
        free(message->body_s3_key);
        free(message->mime_type);
        free(message->encoding);
        free(message);
        
        free(message_data);
        free(mailbox->name);
        free(mailbox->flags);
        free(mailbox->permanent_flags);
        free(mailbox);
        
        send_tagged_no(client, tag, "APPEND failed");
    }
}

// Handle FETCH command
void handle_fetch(ClientState *client, const char *tag, const char *args) {
    if (!client->authenticated || !client->account || !client->current_mailbox) {
        send_tagged_no(client, tag, "Not authenticated or no mailbox selected");
        return;
    }
    
    if (!check_session_timeout(client)) {
        return;
    }
    
    // Parse message sequence and fetch items
    // Simplified implementation - fetches all messages
    char sequence[256];
    char items[256];
    
    if (sscanf(args, "%255s %255s", sequence, items) != 2) {
        send_tagged_bad(client, tag, "Invalid arguments");
        return;
    }
    
    // Get messages from database
    int count;
    Message **messages = db_get_messages(client->current_mailbox->id, 0, 100, &count);
    
    if (!messages) {
        send_tagged_ok(client, tag, "FETCH completed");
        return;
    }
    
    // Process sequence (simplified: handles "1:*" for all messages)
    int start = 1;
    int end = count;
    
    if (strcmp(sequence, "1:*") == 0 || strcmp(sequence, "ALL") == 0) {
        // All messages
        start = 1;
        end = count;
    } else {
        // Single message
        sscanf(sequence, "%d", &start);
        end = start;
    }
    
    // Fetch requested items
    for (int i = start - 1; i < end && i < count; i++) {
        Message *msg = messages[i];
        
        // Fetch body from S3
        size_t body_size;
        char *body = s3_download_message(msg->body_s3_key, &body_size);
        if (!body) {
            continue;
        }
        
        char response[MAX_RESPONSE_LENGTH];
        
        // Check what items are requested
        if (strstr(items, "BODY[]") || strstr(items, "RFC822")) {
            // Full message
            snprintf(response, sizeof(response),
                    "%d FETCH (FLAGS (%s) RFC822.SIZE %d BODY[] {%lu}\r\n",
                    msg->uid, msg->flags, msg->size, (unsigned long)body_size);
            send_untagged(client, response);
            
            // Send body
            send_response(client, body);
            send_response(client, "\r\n)");
            
        } else if (strstr(items, "BODY[HEADER]")) {
            // Just headers (simplified - sends full message)
            snprintf(response, sizeof(response),
                    "%d FETCH (BODY[HEADER] {%lu}\r\n",
                    msg->uid, (unsigned long)body_size);
            send_untagged(client, response);
            
            send_response(client, body);
            send_response(client, "\r\n)");
            
        } else if (strstr(items, "RFC822.SIZE")) {
            // Just size
            snprintf(response, sizeof(response),
                    "%d FETCH (RFC822.SIZE %d)",
                    msg->uid, msg->size);
            send_untagged(client, response);
            
        } else if (strstr(items, "FLAGS")) {
            // Just flags
            snprintf(response, sizeof(response),
                    "%d FETCH (FLAGS (%s))",
                    msg->uid, msg->flags);
            send_untagged(client, response);
            
        } else {
            // Default: envelope info
            snprintf(response, sizeof(response),
                    "%d FETCH (ENVELOPE (\"%s\" \"%s\" (\"%s\" NIL \"%s\" NIL) "
                    "NIL NIL NIL NIL NIL NIL NIL))",
                    msg->uid, msg->envelope_subject, msg->envelope_from,
                    msg->envelope_from, msg->envelope_to);
            send_untagged(client, response);
        }
        
        free(body);
        
        // Free message resources
        free(msg->flags);
        free(msg->envelope_from);
        free(msg->envelope_to);
        free(msg->envelope_subject);
        free(msg->body_s3_key);
        free(msg->mime_type);
        free(msg->encoding);
        free(msg);
    }
    
    free(messages);
    send_tagged_ok(client, tag, "FETCH completed");
}

// Handle STORE command
void handle_store(ClientState *client, const char *tag, const char *args) {
    if (!client->authenticated || !client->account || !client->current_mailbox) {
        send_tagged_no(client, tag, "Not authenticated or no mailbox selected");
        return;
    }
    
    if (!check_session_timeout(client)) {
        return;
    }
    
    // Parse sequence, action, and flags
    char sequence[256];
    char action[64];
    char flags[256];
    
    if (sscanf(args, "%255s %63s %255[^\n]", sequence, action, flags) != 3) {
        send_tagged_bad(client, tag, "Invalid arguments");
        return;
    }
    
    // Parse flags (remove parentheses if present)
    if (flags[0] == '(') {
        memmove(flags, flags + 1, strlen(flags));
        flags[strlen(flags) - 1] = '\0';
    }
    
    // In a full implementation, we would update message flags in database
    // For now, just acknowledge the command
    
    send_tagged_ok(client, tag, "STORE completed");
}

// Handle COPY command
void handle_copy(ClientState *client, const char *tag, const char *args) {
    if (!client->authenticated || !client->account || !client->current_mailbox) {
        send_tagged_no(client, tag, "Not authenticated or no mailbox selected");
        return;
    }
    
    if (!check_session_timeout(client)) {
        return;
    }
    
    char sequence[256];
    char mailbox_name[256];
    
    if (sscanf(args, "%255s \"%255[^\"]\"", sequence, mailbox_name) != 2 &&
        sscanf(args, "%255s %255s", sequence, mailbox_name) != 2) {
        send_tagged_bad(client, tag, "Invalid arguments");
        return;
    }
    
    // Get destination mailbox
    Mailbox *dest_mailbox = db_get_mailbox(client->account->id, mailbox_name);
    if (!dest_mailbox) {
        send_tagged_no(client, tag, "Destination mailbox not found");
        return;
    }
    
    // In a full implementation, we would copy messages
    // For now, just acknowledge the command
    
    free(dest_mailbox->name);
    free(dest_mailbox->flags);
    free(dest_mailbox->permanent_flags);
    free(dest_mailbox);
    
    send_tagged_ok(client, tag, "COPY completed");
}

// Handle UID command
void handle_uid(ClientState *client, const char *tag, const char *args) {
    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }
    
    if (!check_session_timeout(client)) {
        return;
    }
    
    // Parse subcommand
    char subcommand[64];
    char subargs[512];
    
    if (sscanf(args, "%63s %511[^\n]", subcommand, subargs) != 2) {
        strncpy(subcommand, args, sizeof(subcommand) - 1);
        subcommand[sizeof(subcommand) - 1] = '\0';
        subargs[0] = '\0';
    }
    
    // Handle UID FETCH, UID STORE, etc.
    // For now, just pass through to regular commands
    if (strcasecmp(subcommand, "FETCH") == 0) {
        handle_fetch(client, tag, subargs);
    } else if (strcasecmp(subcommand, "STORE") == 0) {
        handle_store(client, tag, subargs);
    } else if (strcasecmp(subcommand, "COPY") == 0) {
        handle_copy(client, tag, subargs);
    } else if (strcasecmp(subcommand, "SEARCH") == 0) {
        // UID SEARCH would be implemented here
        send_tagged_ok(client, tag, "UID SEARCH completed");
    } else {
        send_tagged_bad(client, tag, "Unknown UID command");
    }
}

// Handle EXPUNGE command
void handle_expunge(ClientState *client, const char *tag, const char *args) {
    if (!client->authenticated || !client->account || !client->current_mailbox) {
        send_tagged_no(client, tag, "Not authenticated or no mailbox selected");
        return;
    }
    
    if (!check_session_timeout(client)) {
        return;
    }
    
    // In a full implementation, we would delete messages marked \Deleted
    // For now, just acknowledge
    
    send_tagged_ok(client, tag, "EXPUNGE completed");
}

// Handle SEARCH command
void handle_search(ClientState *client, const char *tag, const char *args) {
    if (!client->authenticated || !client->account || !client->current_mailbox) {
        send_tagged_no(client, tag, "Not authenticated or no mailbox selected");
        return;
    }
    
    if (!check_session_timeout(client)) {
        return;
    }
    
    // Get all message UIDs
    int count;
    Message **messages = db_get_messages(client->current_mailbox->id, 0, 1000, &count);
    
    if (!messages) {
        send_untagged(client, "SEARCH");
        send_tagged_ok(client, tag, "SEARCH completed");
        return;
    }
    
    // Build list of UIDs
    char uid_list[1024] = "";
    for (int i = 0; i < count; i++) {
        char temp[32];
        snprintf(temp, sizeof(temp), "%d ", messages[i]->uid);
        strcat(uid_list, temp);
        
        // Free message resources
        free(messages[i]->flags);
        free(messages[i]->envelope_from);
        free(messages[i]->envelope_to);
        free(messages[i]->envelope_subject);
        free(messages[i]->body_s3_key);
        free(messages[i]->mime_type);
        free(messages[i]->encoding);
        free(messages[i]);
    }
    free(messages);
    
    // Remove trailing space
    if (strlen(uid_list) > 0) {
        uid_list[strlen(uid_list) - 1] = '\0';
    }
    
    // Send search results
    char response[MAX_RESPONSE_LENGTH];
    snprintf(response, sizeof(response), "SEARCH %s", uid_list);
    send_untagged(client, response);
    
    send_tagged_ok(client, tag, "SEARCH completed");
}

// Handle LOGOUT command
void handle_logout(ClientState *client, const char *tag) {
    send_untagged(client, "BYE IMAP4rev1 Server logging out");
    send_tagged_ok(client, tag, "LOGOUT completed");
}

// Handle STARTTLS command
void handle_starttls(ClientState *client, const char *tag, SSL_CTX *ssl_ctx) {
    if (client->use_ssl || client->ssl) {
        send_tagged_no(client, tag, "Already using TLS");
        return;
    }
    
    send_tagged_ok(client, tag, "Begin TLS negotiation now");
    
    // Create SSL object
    client->ssl = SSL_new(ssl_ctx);
    SSL_set_fd(client->ssl, client->socket);
    
    // Perform SSL handshake
    if (SSL_accept(client->ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(client->ssl);
        client->ssl = NULL;
        return;
    }
    
    client->use_ssl = 1;
}

// Client thread function
void* handle_client(void* arg) {
    ClientState *client = (ClientState*)malloc(sizeof(ClientState));
    memcpy(client, arg, sizeof(ClientState));
    free(arg);
    
    // Initialize client state
    client->ssl = NULL;
    client->use_ssl = 0;
    client->authenticated = 0;
    client->account = NULL;
    client->current_mailbox = NULL;
    client->current_mailbox_name[0] = '\0';
    client->session_id[0] = '\0';
    client->last_activity = time(NULL);
    
    // Send greeting
    send_untagged(client, "OK IMAP4rev1 Service Ready");
    
    char buffer[MAX_BUFFER_SIZE];
    char tag[MAX_TAG_LENGTH];
    char command[MAX_COMMAND_LENGTH];
    char args[MAX_BUFFER_SIZE];
    
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        
        // Read command
        ssize_t bytes_received;
        if (client->use_ssl && client->ssl) {
            bytes_received = SSL_read(client->ssl, buffer, sizeof(buffer) - 1);
        } else {
            bytes_received = recv(client->socket, buffer, sizeof(buffer) - 1, 0);
        }
        
        if (bytes_received <= 0) {
            break;
        }
        
        buffer[bytes_received] = '\0';
        
        // Remove trailing newline/carriage return
        char *newline = strchr(buffer, '\r');
        if (newline) *newline = '\0';
        newline = strchr(buffer, '\n');
        if (newline) *newline = '\0';
        
        printf("[%s:%d] Received: %s\n", 
               client->client_ip, client->client_port, buffer);
        
        // Parse command
        if (!parse_command(buffer, tag, command, args)) {
            send_tagged_bad(client, "BAD", "Invalid command");
            continue;
        }
        
        // Process command
        if (strcasecmp(command, "CAPABILITY") == 0) {
            handle_capability(client, tag);
        } else if (strcasecmp(command, "NOOP") == 0) {
            handle_noop(client, tag);
        } else if (strcasecmp(command, "LOGOUT") == 0) {
            handle_logout(client, tag);
            break;
        } else if (strcasecmp(command, "LOGIN") == 0) {
            handle_login(client, tag, args);
        } else if (strcasecmp(command, "SELECT") == 0) {
            handle_select(client, tag, args);
        } else if (strcasecmp(command, "EXAMINE") == 0) {
            handle_examine(client, tag, args);
        } else if (strcasecmp(command, "CREATE") == 0) {
            handle_create(client, tag, args);
        } else if (strcasecmp(command, "DELETE") == 0) {
            handle_delete(client, tag, args);
        } else if (strcasecmp(command, "RENAME") == 0) {
            // Not implemented
            send_tagged_bad(client, tag, "RENAME not implemented");
        } else if (strcasecmp(command, "SUBSCRIBE") == 0) {
            // Not implemented
            send_tagged_bad(client, tag, "SUBSCRIBE not implemented");
        } else if (strcasecmp(command, "UNSUBSCRIBE") == 0) {
            // Not implemented
            send_tagged_bad(client, tag, "UNSUBSCRIBE not implemented");
        } else if (strcasecmp(command, "LIST") == 0) {
            handle_list(client, tag, args);
        } else if (strcasecmp(command, "LSUB") == 0) {
            handle_lsub(client, tag, args);
        } else if (strcasecmp(command, "STATUS") == 0) {
            handle_status(client, tag, args);
        } else if (strcasecmp(command, "APPEND") == 0) {
            handle_append(client, tag, args);
        } else if (strcasecmp(command, "CHECK") == 0) {
            send_tagged_ok(client, tag, "CHECK completed");
        } else if (strcasecmp(command, "CLOSE") == 0) {
            // Clear current mailbox
            if (client->current_mailbox) {
                free(client->current_mailbox->name);
                free(client->current_mailbox->flags);
                free(client->current_mailbox->permanent_flags);
                free(client->current_mailbox);
                client->current_mailbox = NULL;
                client->current_mailbox_name[0] = '\0';
            }
            send_tagged_ok(client, tag, "CLOSE completed");
        } else if (strcasecmp(command, "EXPUNGE") == 0) {
            handle_expunge(client, tag, args);
        } else if (strcasecmp(command, "SEARCH") == 0) {
            handle_search(client, tag, args);
        } else if (strcasecmp(command, "FETCH") == 0) {
            handle_fetch(client, tag, args);
        } else if (strcasecmp(command, "STORE") == 0) {
            handle_store(client, tag, args);
        } else if (strcasecmp(command, "COPY") == 0) {
            handle_copy(client, tag, args);
        } else if (strcasecmp(command, "UID") == 0) {
            handle_uid(client, tag, args);
        } else if (strcasecmp(command, "STARTTLS") == 0) {
            // STARTTLS requires SSL_CTX to be passed
            send_tagged_bad(client, tag, "STARTTLS not available in this context");
        } else if (strcasecmp(command, "AUTHENTICATE") == 0) {
            send_tagged_bad(client, tag, "AUTHENTICATE not implemented");
        } else {
            send_tagged_bad(client, tag, "Unknown command");
        }
    }
    
    // Cleanup
    if (client->ssl) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
    }
    
    if (client->account) {
        free(client->account->username);
        free(client->account->email);
        if (client->account->full_name) free(client->account->full_name);
        free(client->account);
    }
    
    if (client->current_mailbox) {
        free(client->current_mailbox->name);
        free(client->current_mailbox->flags);
        free(client->current_mailbox->permanent_flags);
        free(client->current_mailbox);
    }
    
    close(client->socket);
    free(client);
    
    return NULL;
}

// Initialize SSL
SSL_CTX* init_ssl(void) {
    SSL_CTX *ctx;
    
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    return ctx;
}

// Main server function
int main(int argc, char *argv[]) {
    int server_socket, ssl_server_socket;
    struct sockaddr_in server_addr, ssl_server_addr;
    pthread_t thread_id;
    SSL_CTX *ssl_ctx = NULL;
    
    // Initialize database
    if (!db_init()) {
        fprintf(stderr, "Failed to initialize database\n");
        return 1;
    }
    
    // Initialize S3
    if (!s3_init(S3_ENDPOINT, S3_REGION, S3_ACCESS_KEY, S3_SECRET_KEY, S3_USE_SSL)) {
        fprintf(stderr, "Failed to initialize S3 client\n");
        db_cleanup();
        return 1;
    }
    
    // Initialize SSL for IMAPS
    ssl_ctx = init_ssl();
    if (!ssl_ctx) {
        fprintf(stderr, "Warning: SSL initialization failed, IMAPS will not be available\n");
    }
    
    // Create regular IMAP socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        db_cleanup();
        s3_cleanup();
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        close(server_socket);
        db_cleanup();
        s3_cleanup();
        return 1;
    }
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(IMAP_PORT);
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        db_cleanup();
        s3_cleanup();
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        close(server_socket);
        db_cleanup();
        s3_cleanup();
        return 1;
    }
    
    printf("IMAP server listening on port %d\n", IMAP_PORT);
    
    // Create SSL IMAP socket if SSL is available
    if (ssl_ctx) {
        ssl_server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (ssl_server_socket >= 0) {
            setsockopt(ssl_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            
            ssl_server_addr.sin_family = AF_INET;
            ssl_server_addr.sin_addr.s_addr = INADDR_ANY;
            ssl_server_addr.sin_port = htons(IMAP_SSL_PORT);
            
            if (bind(ssl_server_socket, (struct sockaddr*)&ssl_server_addr, sizeof(ssl_server_addr)) >= 0 &&
                listen(ssl_server_socket, MAX_CLIENTS) >= 0) {
                printf("IMAPS server listening on port %d\n", IMAP_SSL_PORT);
                
                // Create thread for SSL server
                pthread_create(&thread_id, NULL, ssl_server_thread, (void*)ssl_ctx);
                pthread_detach(thread_id);
            } else {
                close(ssl_server_socket);
                ssl_server_socket = -1;
            }
        }
    }
    
    // Accept connections
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }
        
        // Create client state
        ClientState *client_state = malloc(sizeof(ClientState));
        if (!client_state) {
            close(client_socket);
            continue;
        }
        
        client_state->socket = client_socket;
        client_state->ssl = NULL;
        client_state->use_ssl = 0;
        inet_ntop(AF_INET, &client_addr.sin_addr, client_state->client_ip, INET6_ADDRSTRLEN);
        client_state->client_port = ntohs(client_addr.sin_port);
        
        printf("New connection from %s:%d\n", client_state->client_ip, client_state->client_port);
        
        // Create thread for client
        if (pthread_create(&thread_id, NULL, handle_client, client_state) != 0) {
            perror("Thread creation failed");
            free(client_state);
            close(client_socket);
            continue;
        }
        
        pthread_detach(thread_id);
    }
    
    // Cleanup
    close(server_socket);
    if (ssl_server_socket >= 0) close(ssl_server_socket);
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    db_cleanup();
    s3_cleanup();
    
    return 0;
}

// SSL server thread function
void* ssl_server_thread(void* arg) {
    SSL_CTX *ssl_ctx = (SSL_CTX*)arg;
    int ssl_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    if (ssl_server_socket < 0) {
        return NULL;
    }
    
    struct sockaddr_in ssl_server_addr;
    int opt = 1;
    setsockopt(ssl_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    ssl_server_addr.sin_family = AF_INET;
    ssl_server_addr.sin_addr.s_addr = INADDR_ANY;
    ssl_server_addr.sin_port = htons(IMAP_SSL_PORT);
    
    if (bind(ssl_server_socket, (struct sockaddr*)&ssl_server_addr, sizeof(ssl_server_addr)) < 0 ||
        listen(ssl_server_socket, MAX_CLIENTS) < 0) {
        close(ssl_server_socket);
        return NULL;
    }
    
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        pthread_t thread_id;
        
        int client_socket = accept(ssl_server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            continue;
        }
        
        // Create SSL connection
        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_socket);
        
        if (SSL_accept(ssl) <= 0) {
            SSL_free(ssl);
            close(client_socket);
            continue;
        }
        
        // Create client state
        ClientState *client_state = malloc(sizeof(ClientState));
        if (!client_state) {
            SSL_free(ssl);
            close(client_socket);
            continue;
        }
        
        client_state->socket = client_socket;
        client_state->ssl = ssl;
        client_state->use_ssl = 1;
        inet_ntop(AF_INET, &client_addr.sin_addr, client_state->client_ip, INET6_ADDRSTRLEN);
        client_state->client_port = ntohs(client_addr.sin_port);
        
        printf("New SSL connection from %s:%d\n", 
               client_state->client_ip, client_state->client_port);
        
        // Create thread for client
        if (pthread_create(&thread_id, NULL, handle_client, client_state) != 0) {
            free(client_state);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }
        
        pthread_detach(thread_id);
    }
    
    close(ssl_server_socket);
    return NULL;
}