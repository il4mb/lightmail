#include <ctype.h>
#include <db.h>
#include <imap-client.h>
#include <imap.h>
#include <lightmail.h>
#include <log.h>
#include <metrics.h>
#include <openssl/err.h>
#include <s3.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// Sanitize log buffer (remove passwords)
static char *sanitize_log_buffer(char *input, size_t max_len) {
    static char sanitized[1024];
    const char *login_pos = strstr(input, "LOGIN");

    if (!login_pos) {
        safe_strncpy(sanitized, input, sizeof(sanitized));
        return sanitized;
    }

    // Copy up to LOGIN
    size_t prefix_len = (size_t)(login_pos - input + 5); // Include "LOGIN"
    if (prefix_len >= sizeof(sanitized)) {
        prefix_len = sizeof(sanitized) - 1;
    }

    safe_strncpy(sanitized, input, prefix_len + 1);

    // Append sanitized marker
    size_t current_len = strlen(sanitized);
    if (current_len < sizeof(sanitized) - 10) {
        strcat(sanitized, " ***");
    }

    return sanitized;
}

// Client cleanup
static void cleanup_client(ClientState *client) {
    if (!client)
        return;

    LOGI("Cleaning up client session: user=%s ip=%s:%d session_id=%s",
         client->account ? client->account->username : "anonymous",
         client->client_ip, client->client_port,
         client->session_id);

    // Cleanup SSL
    if (client->ssl) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }

    // Cleanup account
    if (client->account) {
        db_free_account(client->account);
        client->account = NULL;
    }

    // Cleanup mailbox
    if (client->current_mailbox) {
        db_free_mailbox(client->current_mailbox);
        client->current_mailbox = NULL;
    }

    // Close socket
    if (client->socket >= 0) {
        close(client->socket);
        client->socket = -1;
    }

    // Decrement client count
    imap_decrement_client();

    free(client);
}

// Validate session timeout with improved logging
static int check_session_timeout(ClientState *client) {
    if (!client)
        return 0;

    time_t now = time(NULL);
    time_t elapsed = now - client->last_activity;

    if (elapsed > SESSION_TIMEOUT) {
        LOGI("Session timeout for user=%s from_ip=%s session_id=%s elapsed=%ld",
             client->account ? client->account->username : "anonymous",
             client->client_ip,
             client->session_id,
             (long)elapsed);

        send_untagged(client, "BYE Session timeout");
        return 0;
    }

    client->last_activity = now;
    return 1;
}

// Safe buffer reader for SSL and non-SSL connections
static ssize_t safe_read(ClientState *client, void *buf, size_t len) {
    if (!client || !buf)
        return -1;

    ssize_t bytes_read;
    if (client->use_ssl && client->ssl) {
        bytes_read = SSL_read(client->ssl, buf, len);
        if (bytes_read <= 0) {
            int ssl_err = SSL_get_error(client->ssl, bytes_read);
            if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                return 0; // Would block
            }
            LOGE("SSL read error: %d", ssl_err);
        }
    } else if(client->socket) {
        bytes_read = recv(client->socket, buf, len, 0);
        if (bytes_read < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGE("Socket read error: %s", strerror(errno));
        }
    }
    return bytes_read;
}

// Safe writer for SSL and non-SSL connections
static ssize_t safe_write(ClientState *client, const void *buf, size_t len) {
    if (!client || !buf)
        return -1;

    ssize_t bytes_written;
    if (client->use_ssl && client->ssl) {
        bytes_written = SSL_write(client->ssl, buf, len);
        if (bytes_written <= 0) {
            int ssl_err = SSL_get_error(client->ssl, bytes_written);
            LOGE("SSL write error: %d", ssl_err);
        }
    } else {
        bytes_written = send(client->socket, buf, len, 0);
        if (bytes_written < 0) {
            LOGE("Socket write error: %s", strerror(errno));
        }
    }
    return bytes_written;
}

// Parse quoted string with proper escaping
static int parse_quoted_string(const char *src, char *dest, size_t dest_size, const char **next) {
    if (!src || !dest || dest_size == 0)
        return 0;

    if (*src != '"')
        return 0;

    src++; // Skip opening quote
    size_t i = 0;
    int escaped = 0;

    while (*src && i < dest_size - 1) {
        if (escaped) {
            dest[i++] = *src;
            escaped = 0;
        } else if (*src == '\\') {
            escaped = 1;
        } else if (*src == '"') {
            dest[i] = '\0';
            if (next)
                *next = src + 1;
            return 1;
        } else {
            dest[i++] = *src;
        }
        src++;
    }

    dest[i] = '\0';
    if (next)
        *next = src;
    return 0; // No closing quote found
}

// Helper to read headers from file
static size_t read_headers_from_file(FILE *file, char *buf, size_t buf_size) {
    if (!file || !buf || buf_size == 0)
        return 0;

    size_t total = 0;
    int in_headers = 1;

    while (in_headers && total < buf_size - 1) {
        int c = fgetc(file);
        if (c == EOF)
            break;

        buf[total++] = (char)c;

        // Check for end of headers (blank line)
        if (total >= 4) {
            if (buf[total - 4] == '\r' && buf[total - 3] == '\n' &&
                buf[total - 2] == '\r' && buf[total - 1] == '\n') {
                in_headers = 0;
            } else if (buf[total - 2] == '\n' && buf[total - 1] == '\n') {
                in_headers = 0;
            }
        }
    }

    buf[total] = '\0';
    return total;
}

// Helper to stream file to client
static void stream_file_to_client(ClientState *client, FILE *file) {
    if (!client || !file)
        return;

    const ImapConfig *cfg = imap_get_config();
    size_t buf_size = cfg ? cfg->buffer_size : 8192;
    if (buf_size < 4096)
        buf_size = 4096;

    char *buffer = malloc(buf_size);
    if (!buffer)
        return;

    rewind(file);
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, buf_size, file)) > 0) {
        send_bytes(client, buffer, bytes_read);
    }

    free(buffer);
}

/**
 * HANDER API
 */
// Handle CAPABILITY command with dynamic capabilities
void handle_capability(ClientState *client, const char *tag) {
    if (!client || !tag)
        return;

    check_session_timeout(client);

    // Base capabilities
    send_untagged(client, "CAPABILITY IMAP4rev1");

    // Authentication capabilities
    if (!client->use_ssl) {
        send_untagged(client, "AUTH=PLAIN");
    }
    send_untagged(client, "STARTTLS");

    if (client->use_ssl) {
        send_untagged(client, "LOGINDISABLED");
    }

    // IMAP extensions
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

    // Custom capabilities
    send_untagged(client, "X-LIGHTMAIL");
    send_untagged(client, "X-S3-STORAGE");

    send_tagged_ok(client, tag, "CAPABILITY completed");
}

// Handle LOGIN command with improved security
void handle_login(ClientState *client, const char *tag, const char *args) {
    if (!client || !tag || !args) {
        send_tagged_bad(client, tag, "Internal error");
        return;
    }

    // Check authentication state
    if (client->authenticated) {
        LOGW("Duplicate login attempt from %s", client->client_ip);
        send_tagged_no(client, tag, "Already authenticated");
        return;
    }

    // Check TLS requirement
    if (client->use_ssl && !client->ssl) {
        send_tagged_no(client, tag, "LOGIN disabled, use STARTTLS first");
        return;
    }

    char username[MAX_USERNAME_LEN + 1] = {0};
    char password[MAX_PASSWORD_LEN + 1] = {0};
    const char *ptr = args;

    // Parse username
    if (*ptr == '"') {
        if (!parse_quoted_string(ptr, username, sizeof(username), &ptr)) {
            send_tagged_bad(client, tag, "Invalid username format");
            return;
        }
    } else {
        size_t len = 0;
        while (*ptr && !isspace(*ptr) && len < MAX_USERNAME_LEN) {
            username[len++] = *ptr++;
        }
        username[len] = '\0';
    }

    // Skip whitespace
    while (*ptr && isspace(*ptr))
        ptr++;

    // Parse password
    if (*ptr == '"') {
        if (!parse_quoted_string(ptr, password, sizeof(password), &ptr)) {
            send_tagged_bad(client, tag, "Invalid password format");
            return;
        }
    } else {
        size_t len = 0;
        while (*ptr && !isspace(*ptr) && len < MAX_PASSWORD_LEN) {
            password[len++] = *ptr++;
        }
        password[len] = '\0';
    }

    // Validate input
    if (username[0] == '\0' || password[0] == '\0') {
        send_tagged_bad(client, tag, "Username and password required");
        return;
    }

    // Extract domain
    char user_only[MAX_USERNAME_LEN + 1] = {0};
    char domain[MAX_USERNAME_LEN + 1] = {0};
    safe_strncpy(user_only, username, sizeof(user_only));

    char *at_sign = strchr(user_only, '@');
    if (at_sign) {
        safe_strncpy(domain, at_sign + 1, sizeof(domain));
        *at_sign = '\0';
    }

    // // Rate limiting check
    // if (metrics_auth_attempts_exceeded(client->client_ip)) {
    //     LOGW("Rate limited login attempt from %s", client->client_ip);
    //     send_tagged_no(client, tag, "Authentication rate limited");
    //     return;
    // }

    // Get account
    Account *account = db_get_account_by_username(username);
    if (!account) {
        LOGE("LOGIN failed: Account not found for username='%s' from_ip=%s", username, client->client_ip);
        // metrics_inc_auth_failures();
        send_tagged_no(client, tag, "LOGIN failed");
        return;
    }

    // Verify password with timing-safe comparison
    int auth_result = db_verify_password(account, password);

    // Clear password from memory
    memset(password, 0, sizeof(password));

    if (!auth_result) {
        LOGE("LOGIN failed for user=%s from_ip=%s", account->username, client->client_ip);
        // metrics_inc_auth_failures();
        db_free_account(account);
        send_tagged_no(client, tag, "LOGIN failed");
        return;
    }

    // Update client state
    client->authenticated = 1;
    client->account = account;
    client->last_activity = time(NULL);

    // Generate secure session ID
    unsigned char random_bytes[16];
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        LOGW("Weak random for session ID, using timestamp");
        snprintf(client->session_id, sizeof(client->session_id), "%s-%ld-%d", user_only, (long)time(NULL), rand());
    } else {
        char hex[33];
        for (int i = 0; i < 16; i++) {
            snprintf(hex + i * 2, 3, "%02x", random_bytes[i]);
        }
        snprintf(client->session_id, sizeof(client->session_id), "%s-%s", user_only, hex);
    }

    LOGI("LOGIN success user=%s domain=%s from_ip=%s session_id=%s", user_only, domain[0] ? domain : "local", client->client_ip, client->session_id);

    // metrics_inc_auth_successes();
    send_tagged_ok(client, tag, "LOGIN completed");
}

// Handle SELECT command with improved error handling
void handle_select(ClientState *client, const char *tag, const char *mailbox_name) {
    if (!client || !tag || !mailbox_name) {
        send_tagged_bad(client, tag, "Internal error");
        return;
    }

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    // Clean previous mailbox
    if (client->current_mailbox) {
        db_free_mailbox(client->current_mailbox);
        client->current_mailbox = NULL;
        client->current_mailbox_name[0] = '\0';
    }

    // Get mailbox using existing function
    Mailbox *mailbox = db_get_mailbox(client->account->id, mailbox_name);
    if (!mailbox) {
        send_tagged_no(client, tag, "Mailbox not found");
        return;
    }

    // Update client state
    client->current_mailbox = mailbox;
    safe_strncpy(client->current_mailbox_name, mailbox_name, sizeof(client->current_mailbox_name));

    // Send mailbox status using existing structure
    char response[MAX_RESPONSE_LEN];

    // Send flags
    snprintf(response, sizeof(response), "* FLAGS (%s)", mailbox->flags ? mailbox->flags : "");
    send_untagged(client, response);

    // Send permanent flags
    snprintf(response, sizeof(response), "* OK [PERMANENTFLAGS (%s)] Flags permitted.", mailbox->permanent_flags ? mailbox->permanent_flags : "");
    send_untagged(client, response);

    // Send message counts
    snprintf(response, sizeof(response), "* %d EXISTS", mailbox->total_messages);
    send_untagged(client, response);

    snprintf(response, sizeof(response), "* %d RECENT", mailbox->recent_messages);
    send_untagged(client, response);

    // Send UID information
    snprintf(response, sizeof(response), "* OK [UIDVALIDITY %d] UIDs valid", mailbox->uid_validity);
    send_untagged(client, response);

    snprintf(response, sizeof(response), "* OK [UIDNEXT %d] Predicted next UID", mailbox->uid_next);
    send_untagged(client, response);

    // Send unseen count if available
    if (mailbox->unseen_messages >= 0) {
        snprintf(response, sizeof(response), "* OK [UNSEEN %d] First unseen message", mailbox->unseen_messages + 1);
        send_untagged(client, response);
    }

    send_tagged_ok(client, tag, "[READ-WRITE] SELECT completed");
}

// Improved APPEND command with streaming
void handle_append(ClientState *client, const char *tag, const char *args) {
    if (!client || !tag || !args) {
        send_tagged_bad(client, tag, "Internal error");
        return;
    }

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    char mailbox_name[MAX_MAILBOX_NAME_LEN + 1] = {0};
    char flags[MAX_FLAGS_LEN + 1] = {0};
    char date_time[64] = {0};
    size_t message_size = 0;

    // Parse arguments
    const char *ptr = args;

    // Parse mailbox name
    if (*ptr == '"') {
        if (!parse_quoted_string(ptr, mailbox_name, sizeof(mailbox_name), &ptr)) {
            send_tagged_bad(client, tag, "Invalid mailbox name");
            return;
        }
    } else {
        size_t len = 0;
        while (*ptr && !isspace(*ptr) && len < MAX_MAILBOX_NAME_LEN) {
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
            send_tagged_bad(client, tag, "Invalid flags format");
            return;
        }
        size_t len = (size_t)(end - ptr);
        if (len > MAX_FLAGS_LEN)
            len = MAX_FLAGS_LEN;
        safe_strncpy(flags, ptr, len + 1);
        ptr = end + 1;

        while (*ptr && isspace(*ptr))
            ptr++;
    }

    // Parse optional date-time
    if (*ptr == '"') {
        if (!parse_quoted_string(ptr, date_time, sizeof(date_time), &ptr)) {
            send_tagged_bad(client, tag, "Invalid date-time format");
            return;
        }
        while (*ptr && isspace(*ptr))
            ptr++;
    }

    // Parse message size
    if (*ptr == '{') {
        ptr++;
        char *endptr;
        unsigned long size = strtoul(ptr, &endptr, 10);
        if (endptr == ptr || *endptr != '}') {
            send_tagged_bad(client, tag, "Invalid message size");
            return;
        }
        message_size = size;
        ptr = endptr + 1;

        // Skip \r\n after literal size
        while (*ptr && isspace(*ptr))
            ptr++;
    } else {
        send_tagged_bad(client, tag, "Message size required");
        return;
    }

    // Validate message size
    const ImapConfig *cfg = imap_get_config();
    if (!cfg) {
        send_tagged_no(client, tag, "Server configuration error");
        return;
    }

    if (message_size == 0) {
        send_tagged_no(client, tag, "Empty message not allowed");
        return;
    }

    if (message_size > cfg->max_message_size) {
        LOGW("Message too large: %zu > %zu from %s",
             message_size, cfg->max_message_size, client->client_ip);
        send_tagged_no(client, tag, "Message too large");
        return;
    }

    // Get mailbox
    Mailbox *mailbox = db_get_mailbox(client->account->id, mailbox_name);
    if (!mailbox) {
        send_tagged_no(client, tag, "Mailbox not found");
        return;
    }

    // Send continuation response
    send_response(client, "+ Ready for literal data\r\n");

    // Create temporary file for streaming
    char tmp_template[] = "/tmp/lightmail_XXXXXX";
    int tmp_fd = mkstemp(tmp_template);
    if (tmp_fd == -1) {
        LOGE("Failed to create temp file: %s", strerror(errno));
        db_free_mailbox(mailbox);
        send_tagged_no(client, tag, "Server storage error");
        return;
    }

    // Stream message to temp file
    size_t bytes_read = 0;
    size_t buffer_size = cfg->buffer_size;
    if (buffer_size < 4096)
        buffer_size = 4096;

    char *buffer = malloc(buffer_size);
    if (!buffer) {
        close(tmp_fd);
        unlink(tmp_template);
        db_free_mailbox(mailbox);
        send_tagged_no(client, tag, "Server memory error");
        return;
    }

    // Read message data
    while (bytes_read < message_size) {
        size_t to_read = message_size - bytes_read;
        if (to_read > buffer_size)
            to_read = buffer_size;

        ssize_t n = safe_read(client, buffer, to_read);
        if (n <= 0) {
            if (n == 0) {
                // Client disconnected
                LOGI("Client disconnected during APPEND from %s",
                     client->client_ip);
            }
            free(buffer);
            close(tmp_fd);
            unlink(tmp_template);
            db_free_mailbox(mailbox);
            return;
        }

        ssize_t written = write(tmp_fd, buffer, n);
        if (written != n) {
            LOGE("Failed to write to temp file: %s", strerror(errno));
            free(buffer);
            close(tmp_fd);
            unlink(tmp_template);
            db_free_mailbox(mailbox);
            send_tagged_no(client, tag, "Server storage error");
            return;
        }

        bytes_read += n;
    }

    free(buffer);
    lseek(tmp_fd, 0, SEEK_SET);

    // Allocate UID
    int next_uid = db_allocate_uid(mailbox->id);
    if (next_uid < 0) {
        LOGE("Failed to allocate UID for mailbox %d", mailbox->id);
        close(tmp_fd);
        unlink(tmp_template);
        db_free_mailbox(mailbox);
        send_tagged_no(client, tag, "Server error");
        return;
    }

    // Upload to S3 using file descriptor
    FILE *tmp_file = fdopen(tmp_fd, "rb");
    if (!tmp_file) {
        LOGE("Failed to open temp file: %s", strerror(errno));
        close(tmp_fd);
        unlink(tmp_template);
        db_free_mailbox(mailbox);
        send_tagged_no(client, tag, "Server error");
        return;
    }

    char *s3_key = s3_upload_message_file(client->account->id, mailbox->id,
                                          next_uid, tmp_file, message_size,
                                          "message/rfc822");
    fclose(tmp_file); // This also closes the fd
    unlink(tmp_template);

    if (!s3_key) {
        LOGE("S3 upload failed for mailbox=%s uid=%d",
             mailbox_name, next_uid);
        db_free_mailbox(mailbox);
        send_tagged_no(client, tag, "Failed to store message");
        return;
    }

    // Create message record
    Message *message = calloc(1, sizeof(Message));
    if (!message) {
        LOGE("Memory allocation failed for message");
        free(s3_key);
        db_free_mailbox(mailbox);
        send_tagged_no(client, tag, "Server error");
        return;
    }

    message->mailbox_id = mailbox->id;
    message->uid = next_uid;
    message->internal_date = time(NULL);
    message->flags = flags[0] ? strdup(flags) : strdup("");
    message->size = message_size;
    message->envelope_from = strdup("Unknown");
    message->envelope_to = strdup(client->account->username);
    message->envelope_subject = strdup("");
    message->body_s3_key = s3_key;
    message->body_size = message_size;
    message->mime_type = strdup("message/rfc822");
    message->encoding = strdup("8bit");

    // Parse headers from temp file for better metadata
    FILE *header_file = fopen(tmp_template, "rb");
    if (header_file) {
        char header_buf[8192];
        size_t header_len = fread(header_buf, 1, sizeof(header_buf) - 1, header_file);
        header_buf[header_len] = '\0';
        fclose(header_file);

        // Simple header parsing
        parse_message_headers(header_buf, message);
    }

    // Store message
    if (db_store_message(message)) {

        LOGI("APPEND success mailbox=%s uid=%d size=%zu user=%s", mailbox_name, next_uid, message_size, client->account->username);

        // Update mailbox counts
        db_update_mailbox_stats(mailbox->id);

        send_tagged_ok(client, tag, "APPEND completed");
    } else {
        LOGE("Failed to store message in DB for mailbox=%s uid=%d", mailbox_name, next_uid);

        // Cleanup S3 object on DB failure
        s3_delete_message(s3_key);
        send_tagged_no(client, tag, "Failed to store message");
    }

    // Cleanup
    db_free_message(message);
    db_free_mailbox(mailbox);
}

// Improved FETCH command with partial fetch support
void handle_fetch(ClientState *client, const char *tag, const char *args) {

    if (!client || !tag || !args) {
        send_tagged_bad(client, tag, "Internal error");
        return;
    }

    if (!client->authenticated || !client->account || !client->current_mailbox) {
        send_tagged_no(client, tag, "Not authenticated or no mailbox selected");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    // Parse arguments
    char sequence[256] = {0};
    char items[512] = {0};

    // Simple parsing - can be enhanced for complex sequences
    if (sscanf(args, "%255s %511[^\n]", sequence, items) != 2) {
        send_tagged_bad(client, tag, "Invalid arguments");
        return;
    }

    // Parse sequence (supports "1", "1:*", "2:4", etc.)
    int start_msg = 1;
    int end_msg = INT_MAX;

    if (strcmp(sequence, "ALL") == 0 || strcmp(sequence, "1:*") == 0) {
        start_msg = 1;
        end_msg = INT_MAX;
    } else if (strchr(sequence, ':')) {
        sscanf(sequence, "%d:%d", &start_msg, &end_msg);
    } else {
        sscanf(sequence, "%d", &start_msg);
        end_msg = start_msg;
    }

    // Validate range
    if (start_msg < 1 || end_msg < start_msg) {
        send_tagged_bad(client, tag, "Invalid message sequence");
        return;
    }

    // Get messages
    int count = 0;
    Message **messages = db_get_messages(client->current_mailbox->id, start_msg, end_msg, &count);
    if (!messages || count == 0) {
        if (messages)
            free(messages);
        send_untagged(client, "FETCH completed");
        send_tagged_ok(client, tag, "FETCH completed");
        return;
    }

    // Process each message
    for (int i = 0; i < count; i++) {
        Message *msg = messages[i];
        if (!msg)
            continue;

        char response[MAX_RESPONSE_LEN];
        int msg_seq = start_msg + i;

        // Check for specific fetch items
        int fetch_body = (strstr(items, "BODY[]") != NULL || strstr(items, "RFC822") != NULL);
        int fetch_headers = (strstr(items, "BODY[HEADER]") != NULL);
        int fetch_size = (strstr(items, "RFC822.SIZE") != NULL);
        int fetch_flags = (strstr(items, "FLAGS") != NULL);
        int fetch_envelope = (strstr(items, "ENVELOPE") != NULL);
        int fetch_uid = (strstr(items, "UID") != NULL);

        // Build FETCH response
        size_t resp_len = 0;
        resp_len += snprintf(response + resp_len, MAX_RESPONSE_LEN - resp_len, "* %d FETCH (", msg_seq);

        // Add UID if requested
        if (fetch_uid) {
            resp_len += snprintf(response + resp_len, MAX_RESPONSE_LEN - resp_len, "UID %d ", msg->uid);
        }

        // Add FLAGS if requested
        if (fetch_flags && msg->flags) {
            resp_len += snprintf(response + resp_len, MAX_RESPONSE_LEN - resp_len, "FLAGS (%s) ", msg->flags);
        }

        // Add size if requested
        if (fetch_size) {
            resp_len += snprintf(response + resp_len, MAX_RESPONSE_LEN - resp_len, "RFC822.SIZE %zu ", msg->size);
        }

        // Stream body if requested
        if (fetch_body || fetch_headers) {
            size_t content_size = 0;
            FILE *content_file = s3_download_message_file(msg->body_s3_key, &content_size);

            if (content_file) {
                if (fetch_body) {
                    resp_len += snprintf(response + resp_len, MAX_RESPONSE_LEN - resp_len, "BODY[] {%zu}\r\n", content_size);
                    send_response(client, response);

                    // Stream content
                    stream_file_to_client(client, content_file);
                    send_response(client, "\r\n");
                } else if (fetch_headers) {
                    // Read just headers (first blank line)
                    char header_buf[8192];
                    size_t header_len = read_headers_from_file(content_file, header_buf, sizeof(header_buf));

                    resp_len += snprintf(response + resp_len, MAX_RESPONSE_LEN - resp_len, "BODY[HEADER] {%zu}\r\n", header_len);
                    send_response(client, response);
                    send_bytes(client, header_buf, header_len);
                    send_response(client, "\r\n");
                }

                fclose(content_file);
            }
        } else if (fetch_envelope) {
            // Send envelope
            resp_len += snprintf(response + resp_len, MAX_RESPONSE_LEN - resp_len,
                                 "ENVELOPE (\"%s\" \"%s\" (\"%s\" NIL \"%s\" NIL) "
                                 "NIL NIL NIL NIL NIL NIL NIL)",
                                 msg->envelope_subject ? msg->envelope_subject : "",
                                 msg->envelope_from ? msg->envelope_from : "",
                                 msg->envelope_from ? msg->envelope_from : "",
                                 msg->envelope_to ? msg->envelope_to : "");
            send_response(client, response);
        }

        // Close FETCH response if not already sent
        if (!fetch_body && !fetch_headers) {
            if (resp_len > 0 && response[resp_len - 1] == ' ') {
                resp_len--;
            }
            resp_len += snprintf(response + resp_len, MAX_RESPONSE_LEN - resp_len, ")");
            send_response(client, response);
        }

        db_free_message(msg);
    }

    free(messages);
    send_tagged_ok(client, tag, "FETCH completed");
}

// Handle NOOP command - No operation, just updates session
void handle_noop(ClientState *client, const char *tag, const char *args) {
    (void)args; // Unused parameter

    if (!client || !tag)
        return;

    check_session_timeout(client);
    send_tagged_ok(client, tag, "NOOP completed");
}

// Handle LOGOUT command - End session
void handle_logout(ClientState *client, const char *tag, const char *args) {
    (void)args; // Unused parameter

    if (!client || !tag)
        return;

    LOGI("LOGOUT: user=%s ip=%s session_id=%s",
         client->account ? client->account->username : "anonymous",
         client->client_ip,
         client->session_id);

    // Send BYE notification
    send_untagged(client, "* BYE IMAP4rev1 Server logging out");

    // Send final OK response
    send_tagged_ok(client, tag, "LOGOUT completed");

    // Client will be cleaned up in handle_client thread
}

// Handle EXAMINE command - Read-only SELECT
void handle_examine(ClientState *client, const char *tag, const char *args) {
    if (!client || !tag || !args) {
        send_tagged_bad(client, tag, "Internal error");
        return;
    }

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    // Call SELECT handler first
    handle_select(client, tag, args);

    // Mark as read-only (in a real implementation, you'd track this in client state)
    LOGI("EXAMINE: user=%s mailbox=%s read-only",
         client->account->username,
         args);
}

// Handle CREATE command - Create new mailbox
void handle_create(ClientState *client, const char *tag, const char *args) {
    if (!client || !tag || !args) {
        send_tagged_bad(client, tag, "Internal error");
        return;
    }

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    char mailbox_name[256] = {0};

    // Parse mailbox name (quoted or literal)
    if (args[0] == '"') {
        const char *end = strchr(args + 1, '"');
        if (!end) {
            send_tagged_bad(client, tag, "Invalid mailbox name");
            return;
        }
        int len = end - (args + 1);
        strncpy(mailbox_name, args + 1, len);
        mailbox_name[len] = '\0';
    } else {
        strncpy(mailbox_name, args, sizeof(mailbox_name) - 1);
        mailbox_name[sizeof(mailbox_name) - 1] = '\0';
    }

    // Validate mailbox name
    if (mailbox_name[0] == '\0') {
        send_tagged_bad(client, tag, "Empty mailbox name");
        return;
    }

    // Check if mailbox already exists
    Mailbox *existing = db_get_mailbox(client->account->id, mailbox_name);
    if (existing) {
        db_free_mailbox(existing);
        send_tagged_no(client, tag, "Mailbox already exists");
        return;
    }

    // Create mailbox in database
    if (db_create_mailbox(client->account->id, mailbox_name, NULL)) {
        LOGI("CREATE: user=%s mailbox=%s success", client->account->username, mailbox_name);
        send_tagged_ok(client, tag, "CREATE completed");
    } else {
        LOGE("CREATE: user=%s mailbox=%s failed",
             client->account->username, mailbox_name);
        send_tagged_no(client, tag, "CREATE failed");
    }
}

// Handle DELETE command - Delete mailbox
void handle_delete(ClientState *client, const char *tag, const char *args) {
    if (!client || !tag || !args) {
        send_tagged_bad(client, tag, "Internal error");
        return;
    }

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    char mailbox_name[256] = {0};

    // Parse mailbox name
    if (args[0] == '"') {
        const char *end = strchr(args + 1, '"');
        if (!end) {
            send_tagged_bad(client, tag, "Invalid mailbox name");
            return;
        }
        int len = end - (args + 1);
        strncpy(mailbox_name, args + 1, len);
        mailbox_name[len] = '\0';
    } else {
        strncpy(mailbox_name, args, sizeof(mailbox_name) - 1);
        mailbox_name[sizeof(mailbox_name) - 1] = '\0';
    }

    // Cannot delete INBOX
    if (strcasecmp(mailbox_name, "INBOX") == 0) {
        send_tagged_no(client, tag, "Cannot delete INBOX");
        return;
    }

    // Get mailbox to check if it exists
    Mailbox *mailbox = db_get_mailbox(client->account->id, mailbox_name);
    if (!mailbox) {
        send_tagged_no(client, tag, "Mailbox not found");
        return;
    }

    // Check if mailbox is currently selected
    if (client->current_mailbox &&
        client->current_mailbox->id == mailbox->id) {
        db_free_mailbox(mailbox);
        send_tagged_no(client, tag, "Cannot delete selected mailbox");
        return;
    }

    // Delete mailbox from database
    if (db_delete_mailbox(mailbox->id)) {
        LOGI("DELETE: user=%s mailbox=%s success",
             client->account->username, mailbox_name);
        send_tagged_ok(client, tag, "DELETE completed");
    } else {
        LOGE("DELETE: user=%s mailbox=%s failed",
             client->account->username, mailbox_name);
        send_tagged_no(client, tag, "DELETE failed");
    }

    db_free_mailbox(mailbox);
}

// Handle LIST command - List mailboxes
void handle_list(ClientState *client, const char *tag, const char *args) {
    if (!client || !tag || !args) {
        send_tagged_bad(client, tag, "Internal error");
        return;
    }

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    char reference[256] = {0};
    char pattern[256] = {0};

    // Parse reference and pattern
    if (sscanf(args, "\"%255[^\"]\" \"%255[^\"]\"", reference, pattern) != 2 &&
        sscanf(args, "%255s %255s", reference, pattern) != 2) {
        send_tagged_bad(client, tag, "Invalid arguments");
        return;
    }

    // Get all mailboxes for the account
    int count = 0;
    Mailbox **mailboxes = db_get_mailboxes(client->account->id, &count);

    if (!mailboxes || count == 0) {
        if (mailboxes)
            free(mailboxes);
        send_tagged_ok(client, tag, "LIST completed");
        return;
    }

    // Send mailbox list
    for (int i = 0; i < count; i++) {
        Mailbox *mb = mailboxes[i];

        // Check if mailbox matches pattern
        // Simple wildcard matching: * matches anything, % matches single level
        int match = 1;

        if (strcmp(pattern, "*") != 0) {
            // Basic pattern matching - for production, implement RFC 3501 spec
            if (strstr(mb->name, pattern) == NULL &&
                strcmp(pattern, "%") != 0) {
                match = 0;
            }
        }

        if (match) {
            char response[MAX_RESPONSE_LENGTH];
            // For simplicity, all mailboxes marked as \\HasNoChildren
            snprintf(response, sizeof(response),
                     "* LIST (\\HasNoChildren) \"/\" \"%s\"", mb->name);
            send_untagged(client, response);
        }

        // Free mailbox structure
        free(mb->name);
        free(mb->flags);
        free(mb->permanent_flags);
        free(mb);
    }

    free(mailboxes);
    send_tagged_ok(client, tag, "LIST completed");
}

// Handle LSUB command - List subscribed mailboxes
void handle_lsub(ClientState *client, const char *tag, const char *args) {
    if (!client || !tag || !args) {
        send_tagged_bad(client, tag, "Internal error");
        return;
    }

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    // For simplicity, treat LSUB same as LIST (all mailboxes are "subscribed")
    // In a real implementation, you'd have a subscription table in the database
    handle_list(client, tag, args);
}

// Handle STATUS command - Get mailbox status
void handle_status(ClientState *client, const char *tag, const char *args) {
    if (!client || !tag || !args) {
        send_tagged_bad(client, tag, "Internal error");
        return;
    }

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    char mailbox_name[256] = {0};
    char status_items[256] = {0};

    // Parse mailbox name and status items
    if (sscanf(args, "\"%255[^\"]\" (%255[^)])", mailbox_name, status_items) != 2 &&
        sscanf(args, "%255s (%255[^)])", mailbox_name, status_items) != 2) {
        send_tagged_bad(client, tag, "Invalid arguments");
        return;
    }

    // Get mailbox
    Mailbox *mailbox = db_get_mailbox(client->account->id, mailbox_name);
    if (!mailbox) {
        send_tagged_no(client, tag, "Mailbox not found");
        return;
    }

    // Build STATUS response
    char response[MAX_RESPONSE_LENGTH];
    int pos = snprintf(response, sizeof(response), "* STATUS \"%s\" (", mailbox_name);

    // Parse requested status items
    char *item = strtok(status_items, " ");
    int first = 1;

    while (item != NULL) {
        if (!first) {
            pos += snprintf(response + pos, sizeof(response) - pos, " ");
        }
        first = 0;

        if (strcasecmp(item, "MESSAGES") == 0) {
            pos += snprintf(response + pos, sizeof(response) - pos,
                            "MESSAGES %d", mailbox->total_messages);
        } else if (strcasecmp(item, "RECENT") == 0) {
            pos += snprintf(response + pos, sizeof(response) - pos,
                            "RECENT %d", mailbox->recent_messages);
        } else if (strcasecmp(item, "UIDNEXT") == 0) {
            pos += snprintf(response + pos, sizeof(response) - pos,
                            "UIDNEXT %d", mailbox->uid_next);
        } else if (strcasecmp(item, "UIDVALIDITY") == 0) {
            pos += snprintf(response + pos, sizeof(response) - pos,
                            "UIDVALIDITY %d", mailbox->uid_validity);
        } else if (strcasecmp(item, "UNSEEN") == 0 && mailbox->unseen_messages >= 0) {
            pos += snprintf(response + pos, sizeof(response) - pos,
                            "UNSEEN %d", mailbox->unseen_messages);
        }
        // Could add more status items here

        item = strtok(NULL, " ");
    }

    pos += snprintf(response + pos, sizeof(response) - pos, ")");
    send_untagged(client, response);

    db_free_mailbox(mailbox);
    send_tagged_ok(client, tag, "STATUS completed");
}

// Handle CHECK command - Checkpoint
void handle_check(ClientState *client, const char *tag, const char *args) {
    (void)args; // Unused parameter

    if (!client || !tag)
        return;

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    // CHECK is essentially a NOOP for most implementations
    send_tagged_ok(client, tag, "CHECK completed");
}

// Handle CLOSE command - Close mailbox and expunge
void handle_close(ClientState *client, const char *tag, const char *args) {
    (void)args; // Unused parameter

    if (!client || !tag)
        return;

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    if (!client->current_mailbox) {
        send_tagged_no(client, tag, "No mailbox selected");
        return;
    }

    LOGI("CLOSE: user=%s mailbox=%s",
         client->account->username,
         client->current_mailbox_name);

    // Perform implicit EXPUNGE (delete messages marked \Deleted)
    // In a real implementation, you would call db_expunge_mailbox()

    // Clear current mailbox
    db_free_mailbox(client->current_mailbox);
    client->current_mailbox = NULL;
    client->current_mailbox_name[0] = '\0';

    send_tagged_ok(client, tag, "CLOSE completed");
}

// Handle EXPUNGE command - Permanently remove messages marked \Deleted
void handle_expunge(ClientState *client, const char *tag, const char *args) {
    (void)args; // Unused parameter

    if (!client || !tag)
        return;

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    if (!client->current_mailbox) {
        send_tagged_no(client, tag, "No mailbox selected");
        return;
    }

    // Get messages marked \Deleted
    int count = 0;
    // Message **deleted_messages = db_get_messages_with_flag(client->current_mailbox->id, "\\Deleted", &count);

    // if (deleted_messages && count > 0) {
    //     // Send EXPUNGE responses for each deleted message
    //     for (int i = 0; i < count; i++) {
    //         // In real implementation, you'd track sequence numbers
    //         // For now, send generic response
    //         send_untagged(client, "* EXPUNGE");

    //         // Delete from S3
    //         s3_delete_message(deleted_messages[i]->body_s3_key);

    //         // Free message structure
    //         db_free_message(deleted_messages[i]);
    //     }

    //     free(deleted_messages);

    //     // Delete from database
    //     // db_delete_messages_with_flag(client->current_mailbox->id, "\\Deleted");

    //     LOGI("EXPUNGE: user=%s mailbox=%s removed=%d messages",
    //          client->account->username,
    //          client->current_mailbox_name,
    //          count);
    // }

    send_tagged_ok(client, tag, "EXPUNGE completed");
}

// Handle SEARCH command - Search for messages
void handle_search(ClientState *client, const char *tag, const char *args) {
    if (!client || !tag || !args) {
        send_tagged_bad(client, tag, "Internal error");
        return;
    }

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    if (!client->current_mailbox) {
        send_tagged_no(client, tag, "No mailbox selected");
        return;
    }

    // For simplicity, implement basic search
    // In production, parse args according to RFC 3501

    int count = 0;
    Message **messages = NULL;

    if (strcasecmp(args, "ALL") == 0 || strlen(args) == 0) {
        // Get all messages
        messages = db_get_messages(client->current_mailbox->id, 0, 1000, &count);
    } else if (strstr(args, "UNSEEN") != NULL) {
        // Get unseen messages
        // messages = db_get_messages_with_flag(client->current_mailbox->id, "\\Seen", &count);
        // Need to invert - get messages WITHOUT \Seen flag
        // Simplified for now
    }

    // Build search results
    char response[MAX_RESPONSE_LENGTH] = "* SEARCH";
    size_t resp_len = strlen(response);

    if (messages && count > 0) {
        for (int i = 0; i < count; i++) {
            int remaining = sizeof(response) - resp_len - 1;
            if (remaining < 20)
                break; // Avoid overflow

            int n = snprintf(response + resp_len, remaining, " %d", messages[i]->uid);
            if (n > 0)
                resp_len += n;

            db_free_message(messages[i]);
        }
        free(messages);
    }

    send_untagged(client, response);
    send_tagged_ok(client, tag, "SEARCH completed");
}

// Handle STORE command - Modify message flags
void handle_store(ClientState *client, const char *tag, const char *args) {
    if (!client || !tag || !args) {
        send_tagged_bad(client, tag, "Internal error");
        return;
    }

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    if (!client->current_mailbox) {
        send_tagged_no(client, tag, "No mailbox selected");
        return;
    }

    char sequence[256] = {0};
    char action[64] = {0};
    char flags[512] = {0};

    // Parse: sequence store_action flags
    if (sscanf(args, "%255s %63s %511[^\n]", sequence, action, flags) != 3) {
        send_tagged_bad(client, tag, "Invalid arguments");
        return;
    }

    // Remove parentheses from flags if present
    if (flags[0] == '(') {
        memmove(flags, flags + 1, strlen(flags));
        if (flags[strlen(flags) - 1] == ')') {
            flags[strlen(flags) - 1] = '\0';
        }
    }

    // Parse sequence (simplified - only supports single message or ALL)
    int start_msg = 1;
    int end_msg = 1;

    if (strcmp(sequence, "ALL") == 0 || strcmp(sequence, "1:*") == 0) {
        start_msg = 1;
        end_msg = INT_MAX;
    } else if (strchr(sequence, ':')) {
        sscanf(sequence, "%d:%d", &start_msg, &end_msg);
    } else {
        sscanf(sequence, "%d", &start_msg);
        end_msg = start_msg;
    }

    // Get messages in range
    int offset = start_msg - 1;
    int limit = (end_msg == INT_MAX) ? 1000 : (end_msg - start_msg + 1);

    int count = 0;
    Message **messages = db_get_messages(client->current_mailbox->id, offset, limit, &count);

    if (!messages || count == 0) {
        if (messages)
            free(messages);
        send_tagged_ok(client, tag, "STORE completed");
        return;
    }

    // Update flags for each message
    for (int i = 0; i < count; i++) {
        Message *msg = messages[i];

        // Apply flag change based on action
        if (strcasecmp(action, "FLAGS") == 0) {
            // Replace all flags
            db_update_message_flags(msg->id, flags);
        } else if (strcasecmp(action, "+FLAGS") == 0) {
            // Add flags
            char new_flags[512];
            snprintf(new_flags, sizeof(new_flags), "%s %s", msg->flags, flags);
            db_update_message_flags(msg->id, new_flags);
        } else if (strcasecmp(action, "-FLAGS") == 0) {
            // Remove flags (simplified - doesn't parse individual flags)
            // In production, parse flags and remove specific ones
            db_update_message_flags(msg->id, "");
        } else if (strcasecmp(action, "FLAGS.SILENT") == 0) {
            // Same as FLAGS but don't send untagged responses
            db_update_message_flags(msg->id, flags);
            continue; // Skip untagged response
        }

        // Send FETCH response with new flags (unless SILENT)
        if (strcasecmp(action, "FLAGS.SILENT") != 0) {
            char response[MAX_RESPONSE_LENGTH];
            int msg_seq = start_msg + i;
            snprintf(response, sizeof(response),
                     "* %d FETCH (FLAGS (%s))", msg_seq, flags);
            send_untagged(client, response);
        }

        db_free_message(msg);
    }

    free(messages);
    send_tagged_ok(client, tag, "STORE completed");
}

// Handle COPY command - Copy messages to another mailbox
void handle_copy(ClientState *client, const char *tag, const char *args) {
    if (!client || !tag || !args) {
        send_tagged_bad(client, tag, "Internal error");
        return;
    }

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    if (!client->current_mailbox) {
        send_tagged_no(client, tag, "No mailbox selected");
        return;
    }

    char sequence[256] = {0};
    char mailbox_name[256] = {0};

    // Parse: sequence mailbox_name
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

    // Parse sequence (simplified)
    int start_msg = 1;
    int end_msg = 1;

    if (strcmp(sequence, "ALL") == 0 || strcmp(sequence, "1:*") == 0) {
        start_msg = 1;
        end_msg = INT_MAX;
    } else if (strchr(sequence, ':')) {
        sscanf(sequence, "%d:%d", &start_msg, &end_msg);
    } else {
        sscanf(sequence, "%d", &start_msg);
        end_msg = start_msg;
    }

    // Get messages to copy
    int offset = start_msg - 1;
    int limit = (end_msg == INT_MAX) ? 1000 : (end_msg - start_msg + 1);

    int count = 0;
    Message **messages = db_get_messages(client->current_mailbox->id, offset, limit, &count);

    if (!messages || count == 0) {
        if (messages)
            free(messages);
        db_free_mailbox(dest_mailbox);
        send_tagged_ok(client, tag, "COPY completed");
        return;
    }

    // Copy each message
    int copied = 0;
    for (int i = 0; i < count; i++) {
        Message *src_msg = messages[i];

        // Copy message to destination mailbox
        // if (db_copy_message(src_msg->id, dest_mailbox->id)) {
        //     copied++;
        // }

        db_free_message(src_msg);
    }

    free(messages);
    db_free_mailbox(dest_mailbox);

    LOGI("COPY: user=%s src=%s dest=%s copied=%d",
         client->account->username,
         client->current_mailbox_name,
         mailbox_name,
         copied);

    send_tagged_ok(client, tag, "COPY completed");
}

// Handle UID command - UID versions of other commands
void handle_uid(ClientState *client, const char *tag, const char *args) {
    if (!client || !tag || !args) {
        send_tagged_bad(client, tag, "Internal error");
        return;
    }

    if (!client->authenticated || !client->account) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    if (!check_session_timeout(client)) {
        return;
    }

    if (!client->current_mailbox) {
        send_tagged_no(client, tag, "No mailbox selected");
        return;
    }

    char command[64] = {0};
    char subargs[512] = {0};

    // Parse: command subargs
    if (sscanf(args, "%63s %511[^\n]", command, subargs) != 2) {
        strncpy(command, args, sizeof(command) - 1);
        command[sizeof(command) - 1] = '\0';
        subargs[0] = '\0';
    }

    // Route to appropriate handler
    if (strcasecmp(command, "FETCH") == 0) {
        // UID FETCH - would need to convert UIDs to sequence numbers
        // For now, just pass through
        handle_fetch(client, tag, subargs);
    } else if (strcasecmp(command, "STORE") == 0) {
        // UID STORE
        handle_store(client, tag, subargs);
    } else if (strcasecmp(command, "COPY") == 0) {
        // UID COPY
        handle_copy(client, tag, subargs);
    } else if (strcasecmp(command, "SEARCH") == 0) {
        // UID SEARCH - returns UIDs instead of sequence numbers
        handle_search(client, tag, subargs);
        // Note: Actual implementation would need to modify search to return UIDs
    } else {
        send_tagged_bad(client, tag, "Unknown UID command");
    }
}

// Process IMAP command with centralized dispatch
static void process_imap_command(ClientState *client, const char *tag, const char *command, const char *args) {
    if (!client || !tag || !command)
        return;

    // Command dispatch table
    typedef struct {
        const char *name;
        void (*handler)(ClientState *, const char *, const char *);
        int requires_auth;
        int requires_mailbox;
    } CommandHandler;

    static const CommandHandler handlers[] = {
        {"CAPABILITY", handle_capability, 0, 0},
        {"NOOP", handle_noop, 0, 0},
        {"LOGOUT", handle_logout, 0, 0},
        {"LOGIN", handle_login, 0, 0},
        {"SELECT", handle_select, 1, 0},
        {"EXAMINE", handle_examine, 1, 0},
        {"CREATE", handle_create, 1, 0},
        {"DELETE", handle_delete, 1, 0},
        {"LIST", handle_list, 1, 0},
        {"LSUB", handle_lsub, 1, 0},
        {"STATUS", handle_status, 1, 0},
        {"APPEND", handle_append, 1, 0},
        {"CHECK", handle_check, 1, 1},
        {"CLOSE", handle_close, 1, 1},
        {"EXPUNGE", handle_expunge, 1, 1},
        {"SEARCH", handle_search, 1, 1},
        {"FETCH", handle_fetch, 1, 1},
        {"STORE", handle_store, 1, 1},
        {"COPY", handle_copy, 1, 1},
        {"UID", handle_uid, 1, 1},
        {NULL, NULL, 0, 0}};

    // Find handler
    const CommandHandler *handler = NULL;
    for (int i = 0; handlers[i].name; i++) {
        if (strcasecmp(command, handlers[i].name) == 0) {
            handler = &handlers[i];
            break;
        }
    }

    if (!handler) {
        send_tagged_bad(client, tag, "Unknown command");
        return;
    }

    // Check authentication
    if (handler->requires_auth && (!client->authenticated || !client->account)) {
        send_tagged_no(client, tag, "Not authenticated");
        return;
    }

    // Check mailbox selection
    if (handler->requires_mailbox && !client->current_mailbox) {
        send_tagged_no(client, tag, "No mailbox selected");
        return;
    }

    // Check session timeout
    if (!check_session_timeout(client)) {
        return;
    }

    // Execute handler
    handler->handler(client, tag, args);
}

// Enhanced client thread with better resource management
void *handle_client(void *arg) {
    if (!arg)
        return NULL;

    ClientState *client = (ClientState *)arg;
    const ImapConfig *cfg = imap_get_config();

    LOGI("Client connected from %s:%d", client->client_ip, client->client_port);

    if (!cfg) {
        LOGE("No IMAP configuration available");
        close(client->socket);
        free(client);
        imap_decrement_client();
        return NULL;
    }

    // Initialize client state
    client->last_activity = time(NULL);
    client->welcome_sent = 0;

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = cfg->timeout;
    tv.tv_usec = 0;
    setsockopt(client->socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client->socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Send greeting
    send_untagged(client, "* OK IMAP4rev1 LightMail Server Ready");
    client->welcome_sent = 1;

    // Main command loop
    char buffer[cfg->buffer_size + 1];
    char tag[100];
    char command[256];
    char args[cfg->buffer_size];

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        memset(tag, 0, sizeof(tag));
        memset(command, 0, sizeof(command));
        memset(args, 0, sizeof(args));

        // Read command
        ssize_t bytes_received = safe_read(client, buffer, sizeof(buffer) - 1);

        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                LOGI("Client disconnected: %s:%d", client->client_ip, client->client_port);
            }
            break;
        }

        buffer[bytes_received] = '\0';

        // Log command (sanitized for sensitive data)
        if (strncasecmp(buffer, "LOGIN", 5) != 0) {
            LOGD("Command from %s:%d: %s", client->client_ip, client->client_port, sanitize_log_buffer(buffer, sizeof(buffer)));
        }

        // Parse command
        if (!parse_command(buffer, tag, command, args)) {
            send_tagged_bad(client, tag[0] ? tag : "BAD", "Invalid command");
            continue;
        }

        // Process command
        process_imap_command(client, tag, command, args);

        // Check for LOGOUT command
        if (strcasecmp(command, "LOGOUT") == 0) {
            break;
        }
    }

    // Cleanup
    cleanup_client(client);
    return NULL;
}
