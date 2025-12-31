#include "conf.h"
#include "imap.h"
#include "imap-client.h"
#include "db.h"
#include "s3.h"
#include "log.h"
#include "metrics.h"
#include <ctype.h>
#include <openssl/err.h>

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
        while (*args && isspace(*args))
            args++;

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
        metrics_inc_auth_failures();
        send_tagged_no(client, tag, "LOGIN failed");
        return;
    }

    // Verify password
    if (!db_verify_password(account, password)) {
        /* Log failed login */
        log_emit(LOG_LEVEL_WARN, "auth", account->email, NULL, "LOGIN failed for user=%s from_ip=%s", account->email, client->client_ip);
        metrics_inc_auth_failures();
        free(account->username);
        free(account->email);
        if (account->full_name)
            free(account->full_name);
        free(account);
        send_tagged_no(client, tag, "LOGIN failed");
        return;
    }

    // Update client state
    client->authenticated = 1;
    client->account = account;
    client->last_activity = time(NULL);

    // Generate session ID
    snprintf(client->session_id, sizeof(client->session_id), "%s-%s-%ld", user_only, domain, time(NULL));

    /* Log successful login */
    log_emit(LOG_LEVEL_INFO, "auth", client->account ? client->account->email : NULL, client->session_id, "LOGIN success from_ip=%s", client->client_ip);

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

    /* Log mailbox selection */
    log_emit(LOG_LEVEL_INFO, "imap", client->account ? client->account->email : NULL, client->session_id, "SELECT mailbox=%s total=%d unseen=%d", mailbox_name, mailbox->total_messages, mailbox->unseen_messages);

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
    snprintf(response, sizeof(response), "OK [UIDVALIDITY %d] UIDs valid", mailbox->uid_validity);
    send_untagged(client, response);

    snprintf(response, sizeof(response), "OK [UIDNEXT %d] Predicted next UID", mailbox->uid_next);
    send_untagged(client, response);

    // Send unseen count if available
    if (mailbox->unseen_messages >= 0) {
        snprintf(response, sizeof(response), "OK [UNSEEN %d] First unseen message", mailbox->unseen_messages + 1);
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
        log_emit(LOG_LEVEL_INFO, "imap", client->account ? client->account->email : NULL, client->session_id, "CREATE mailbox=%s", mailbox_name);
        send_tagged_ok(client, tag, "CREATE completed");
    } else {
        log_emit(LOG_LEVEL_ERROR, "imap", client->account ? client->account->email : NULL, client->session_id, "CREATE failed mailbox=%s", mailbox_name);
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
        log_emit(LOG_LEVEL_INFO, "imap", client->account ? client->account->email : NULL, client->session_id, "DELETE mailbox=%s", mailbox_name);
        send_tagged_ok(client, tag, "DELETE completed");
    } else {
        log_emit(LOG_LEVEL_ERROR, "imap", client->account ? client->account->email : NULL, client->session_id, "DELETE failed mailbox=%s", mailbox_name);
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
            snprintf(response, sizeof(response), "LIST (\\HasNoChildren) \"/\" \"%s\"", mailboxes[i]->name);
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
    int pos = snprintf(response, sizeof(response), "STATUS \"%s\" (", mailbox_name);
    char temp[256];

    int first = 1;
    while (item) {
        if (!first) {
            pos += snprintf(response + pos, sizeof(response) - pos, " ");
        }
        first = 0;

        if (strcasecmp(item, "MESSAGES") == 0) {
            snprintf(temp, sizeof(temp), "MESSAGES %d", mailbox->total_messages);
            pos += snprintf(response + pos, sizeof(response) - pos, "%s", temp);
        } else if (strcasecmp(item, "RECENT") == 0) {
            snprintf(temp, sizeof(temp), "RECENT %d", mailbox->recent_messages);
            pos += snprintf(response + pos, sizeof(response) - pos, "%s", temp);
        } else if (strcasecmp(item, "UIDNEXT") == 0) {
            snprintf(temp, sizeof(temp), "UIDNEXT %d", mailbox->uid_next);
            pos += snprintf(response + pos, sizeof(response) - pos, "%s", temp);
        } else if (strcasecmp(item, "UIDVALIDITY") == 0) {
            snprintf(temp, sizeof(temp), "UIDVALIDITY %d", mailbox->uid_validity);
            pos += snprintf(response + pos, sizeof(response) - pos, "%s", temp);
        } else if (strcasecmp(item, "UNSEEN") == 0 && mailbox->unseen_messages >= 0) {
            snprintf(temp, sizeof(temp), "UNSEEN %d", mailbox->unseen_messages);
            pos += snprintf(response + pos, sizeof(response) - pos, "%s", temp);
        }

        item = strtok(NULL, " ");
    }

    pos += snprintf(response + pos, sizeof(response) - pos, ")");
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
    while (*ptr && isspace(*ptr))
        ptr++;

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
        while (*ptr && isspace(*ptr))
            ptr++;
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
        while (*ptr && isspace(*ptr))
            ptr++;
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
        while (*ptr && isspace(*ptr))
            ptr++;
    } else {
        send_tagged_bad(client, tag, "Message size required");
        return;
    }

    // Enforce max message size
    const ImapConfig *cfg = get_config_imap();
    if (message_size > cfg->max_message_size) {
        send_tagged_no(client, tag, "Message too large");
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

    size_t buf_size = get_config_imap()->buffer_size;
    if (buf_size < 1024) buf_size = 8192;

    char *buffer = malloc(buf_size);
    if (!buffer) {
        free(mailbox->name);
        free(mailbox->flags);
        free(mailbox->permanent_flags);
        free(mailbox);
        send_tagged_no(client, tag, "Server error");
        return;
    }

    FILE *tmp = tmpfile();
    char *message_data = NULL; /* fallback if tmpfile() fails */
    size_t bytes_read = 0;
    const size_t header_limit = 16384;
    char header_buf[header_limit];
    size_t header_len = 0;

    if (!tmp) {
        /* Fallback: allocate in memory (last resort) */
        message_data = malloc(message_size + 1);
        if (!message_data) {
            free(buffer);
            db_free_mailbox(mailbox);
            send_tagged_no(client, tag, "Server error");
            return;
        }

        while (bytes_read < message_size) {
            ssize_t n;
            size_t to_read = message_size - bytes_read;
            if (to_read > (ssize_t)buf_size)
                to_read = buf_size;

            if (client->use_ssl && client->ssl) {
                n = SSL_read(client->ssl, message_data + bytes_read, to_read);
            } else {
                n = recv(client->socket, message_data + bytes_read, to_read, 0);
            }

            if (n <= 0) {
                free(message_data);
                free(buffer);
                free(mailbox->name);
                free(mailbox->flags);
                free(mailbox->permanent_flags);
                free(mailbox);
                return;
            }

            /* Save headers into header_buf for minimal parsing */
            if (header_len < header_limit) {
                size_t copy_n = n;
                if (header_len + copy_n > header_limit)
                    copy_n = header_limit - header_len;
                memcpy(header_buf + header_len, message_data + bytes_read, copy_n);
                header_len += copy_n;
            }

            bytes_read += n;
        }
        message_data[message_size] = '\0';
    } else {
        while (bytes_read < message_size) {
            ssize_t n;
            size_t to_read = message_size - bytes_read;
            if (to_read > buf_size)
                to_read = buf_size;

            if (client->use_ssl && client->ssl) {
                n = SSL_read(client->ssl, buffer, to_read);
            } else {
                n = recv(client->socket, buffer, to_read, 0);
            }

            if (n <= 0) {
                fclose(tmp);
                free(buffer);
                free(mailbox->name);
                free(mailbox->flags);
                free(mailbox->permanent_flags);
                free(mailbox);
                return;
            }

            if (fwrite(buffer, 1, n, tmp) != (size_t)n) {
                fclose(tmp);
                free(buffer);
                free(mailbox->name);
                free(mailbox->flags);
                free(mailbox->permanent_flags);
                free(mailbox);
                send_tagged_no(client, tag, "Failed to write to temporary storage");
                return;
            }

            if (header_len < header_limit) {
                size_t copy_n = n;
                if (header_len + copy_n > header_limit)
                    copy_n = header_limit - header_len;
                memcpy(header_buf + header_len, buffer, copy_n);
                header_len += copy_n;
            }

            bytes_read += n;
        }
        free(buffer);
        rewind(tmp);
    }

    /* Ensure header buffer is NUL-terminated for parsing */
    if (header_len < header_limit)
        header_buf[header_len] = '\0';
    else
        header_buf[header_limit - 1] = '\0';

    // Get next UID
    int next_uid = db_get_next_uid(mailbox->id);
    if (next_uid < 0) {
        if (tmp) fclose(tmp);
        if (message_data) free(message_data);
        free(mailbox->name);
        free(mailbox->flags);
        free(mailbox->permanent_flags);
        free(mailbox);
        send_tagged_no(client, tag, "Server error");
        return;
    }

    /* Upload message to S3. Prefer streaming from temporary file to avoid holding the whole message in memory. */
    char *s3_key = NULL;
    if (tmp) {
        s3_key = s3_upload_message_file(client->account->id, mailbox->id, next_uid, tmp, message_size, "message/rfc822");
        fclose(tmp);
    } else {
        s3_key = s3_upload_message(client->account->id, mailbox->id, next_uid, message_data, message_size, "message/rfc822");
    }

    if (!s3_key) {
        /* Log failure to store */
        log_emit(LOG_LEVEL_ERROR, "imap", client->account ? client->account->email : NULL, client->session_id, "APPEND failed: s3 upload failed mailbox=%s uid=%d size=%zu", mailbox_name, next_uid, message_size);
        if (message_data) free(message_data);
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
        if (message_data) free(message_data);
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

    /* Parse basic envelope info from the saved header buffer or fallback to the in-memory message */
    char *from = NULL;
    char *subject = NULL;

    if (header_len > 0) {
        from = strstr(header_buf, "\nFrom:");
        if (!from) from = strstr(header_buf, "\r\nFrom:");
        subject = strstr(header_buf, "\nSubject:");
        if (!subject) subject = strstr(header_buf, "\r\nSubject:");
    }

    if (!from && message_data)
        from = strstr(message_data, "\nFrom:");
    if (!subject && message_data)
        subject = strstr(message_data, "\nSubject:");

    if (from) {
        from += 6; // Skip "From:"
        while (*from && isspace(*from))
            from++;
        char *end = strchr(from, '\n');
        if (!end) end = strchr(from, '\r');
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
        while (*subject && isspace(*subject))
            subject++;
        char *end = strchr(subject, '\n');
        if (!end) end = strchr(subject, '\r');
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
        /* Log successful append */
        log_emit(LOG_LEVEL_INFO, "imap", client->account ? client->account->email : NULL, client->session_id, "APPEND completed mailbox=%s uid=%d size=%zu s3=%s", mailbox_name, next_uid, message_size, s3_key);

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
        /* Log failure storing to DB */
        log_emit(LOG_LEVEL_ERROR, "imap", client->account ? client->account->email : NULL, client->session_id, "APPEND failed: db_store_message failed mailbox=%s uid=%d s3=%s", mailbox_name, next_uid, s3_key);

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

        // Fetch body from S3 using streaming to a temporary file
        size_t body_size = 0;
        FILE *tmp = s3_download_message_file(msg->body_s3_key, &body_size);
        if (!tmp) {
            /* Log S3 download failure */
            log_emit(LOG_LEVEL_WARN, "imap", client->account ? client->account->email : NULL, client->session_id, "FETCH warning: s3 download failed key=%s uid=%d", msg->body_s3_key, msg->uid);
            continue;
        }

        /* Log streaming start */
        log_emit(LOG_LEVEL_INFO, "imap", client->account ? client->account->email : NULL, client->session_id, "FETCH streaming uid=%d size=%zu s3=%s", msg->uid, body_size, msg->body_s3_key);

        char response[MAX_RESPONSE_LENGTH];

        // Check what items are requested
        if (strstr(items, "BODY[]") || strstr(items, "RFC822")) {
            // Full message
            snprintf(response, sizeof(response),
                     "%d FETCH (FLAGS (%s) RFC822.SIZE %d BODY[] {%lu}\r\n",
                     msg->uid, msg->flags, msg->size, (unsigned long)body_size);
            send_untagged(client, response);

            /* Log start of streaming body for this message */
            log_emit(LOG_LEVEL_DEBUG, "imap", client->account ? client->account->email : NULL, client->session_id, "FETCH start uid=%d size=%zu s3=%s", msg->uid, body_size, msg->body_s3_key);

            // Stream body from file
            rewind(tmp);
            size_t bufsize = get_config_imap()->buffer_size;
            if (bufsize < 1024) bufsize = 8192;
            char *buf = malloc(bufsize);
            if (buf) {
                size_t n;
                while ((n = fread(buf, 1, bufsize, tmp)) > 0) {
                    send_bytes(client, buf, n);
                }
                free(buf);
            }
            send_response(client, "\r\n)");

            /* Log completion of streaming */
            log_emit(LOG_LEVEL_INFO, "imap", client->account ? client->account->email : NULL, client->session_id, "FETCH complete uid=%d size=%zu s3=%s", msg->uid, body_size, msg->body_s3_key);

        } else if (strstr(items, "BODY[HEADER]")) {
            // Just headers (simplified - sends full message)
            snprintf(response, sizeof(response),
                     "%d FETCH (BODY[HEADER] {%lu}\r\n",
                     msg->uid, (unsigned long)body_size);
            send_untagged(client, response);

            rewind(tmp);
            size_t bufsize = get_config_imap()->buffer_size;
            if (bufsize < 1024) bufsize = 8192;
            char *buf = malloc(bufsize);
            if (buf) {
                size_t n;
                while ((n = fread(buf, 1, bufsize, tmp)) > 0) {
                    send_bytes(client, buf, n);
                }
                free(buf);
            }
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

        if (tmp) fclose(tmp);

        // Free message resources
        db_free_message(msg);
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

    log_emit(LOG_LEVEL_INFO, "imap", client->account ? client->account->email : NULL, client->session_id, "COPY dest=%s", mailbox_name);

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
    size_t uid_pos = 0;
    for (int i = 0; i < count; i++) {
        int n = snprintf(uid_list + uid_pos, sizeof(uid_list) - uid_pos, "%d ", messages[i]->uid);
        if (n > 0) uid_pos += (size_t)n;

        // Free message resources
        free(messages[i]->flags);
        free(messages[i]->envelope_from);
        free(messages[i]->envelope_to);
        free(messages[i]->envelope_subject);
        free(messages[i]->body_s3_key);
        free(messages[i]->mime_type);
        free(messages[i]->encoding);
        free(messages[i]);

        if (uid_pos >= sizeof(uid_list) - 1) break; /* avoid overflow */
    }
    free(messages);

    // Remove trailing space
    if (uid_pos > 0 && uid_list[uid_pos - 1] == ' ') {
        uid_list[uid_pos - 1] = '\0';
    }

    // Send search results
    char response[MAX_RESPONSE_LENGTH];
    snprintf(response, sizeof(response), "SEARCH %s", uid_list);
    send_untagged(client, response);

    send_tagged_ok(client, tag, "SEARCH completed");
}

// Handle LOGOUT command
void handle_logout(ClientState *client, const char *tag) {
    log_emit(LOG_LEVEL_INFO, "imap", client->account ? client->account->email : NULL, client->session_id, "LOGOUT session_end");
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
void *handle_client(void *arg) {

    const ImapConfig *cfg = get_config_imap();
    ClientState *client = (ClientState *)arg;

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

    char buffer[cfg->buffer_size];
    char tag[100];
    char command[255];
    char args[cfg->buffer_size];

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
        if (newline)
            *newline = '\0';
        newline = strchr(buffer, '\n');
        if (newline)
            *newline = '\0';

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
                db_free_mailbox(client->current_mailbox);
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
        db_free_account(client->account);
    }

    if (client->current_mailbox) {
        db_free_mailbox(client->current_mailbox);
    }

    close(client->socket);

    /* Decrement server client count */
    imap_decrement_client();

    free(client);

    return NULL;
}
