#include "lmtp_session.h"
#include "log.h"
#include "s3.h"
#include "db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#define LMTP_BUFFER_SIZE 4096

// Forward declarations for internal functions
static void lmtp_session_init(lmtp_session_t* session, int client_fd);
static void lmtp_session_cleanup(lmtp_session_t* session);
static void send_response(int fd, const char* code, const char* message);
static int process_lmtp_command(lmtp_session_t* session, char* command);
static int handle_data_phase(lmtp_session_t* session);

void handle_lmtp_session(int client_fd) {
    lmtp_session_t session;
    lmtp_session_init(&session, client_fd);

    log_emit(LOG_LEVEL_INFO, "lmtp", NULL, NULL, "New LMTP session started");

    send_response(client_fd, "220", "lightmail LMTP ready");
    session.state = LMTP_STATE_LHLO;

    char buffer[LMTP_BUFFER_SIZE];
    ssize_t nread;

    while ((nread = read(client_fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[nread] = '\0';
        if (process_lmtp_command(&session, buffer) == 0) {
            break; 
        }
    }

    if (nread == -1) {
        log_emit(LOG_LEVEL_ERROR, "lmtp", NULL, NULL, "Read error from client");
    }

    log_emit(LOG_LEVEL_INFO, "lmtp", NULL, NULL, "LMTP session ended");
    lmtp_session_cleanup(&session);
    close(client_fd);
}

static int process_lmtp_command(lmtp_session_t* session, char* command) {
    command[strcspn(command, "\r\n")] = 0;
    log_emit(LOG_LEVEL_DEBUG, "lmtp", NULL, NULL, "C: %s", command);

    if (strncasecmp(command, "QUIT", 4) == 0) {
        send_response(session->client_fd, "221", "Bye");
        return 0;
    } else if (strncasecmp(command, "LHLO ", 5) == 0) {
        // TODO: Validate hostname
        strncpy(session->client_hostname, command + 5, sizeof(session->client_hostname) - 1);
        send_response(session->client_fd, "250", "OK");
        session->state = LMTP_STATE_MAIL;
    } else if (strncasecmp(command, "MAIL FROM:", 10) == 0) {
        // TODO: Parse email address
        session->mail_from = strdup(command + 10);
        send_response(session->client_fd, "250", "OK");
        session->state = LMTP_STATE_RCPT;
    } else if (strncasecmp(command, "RCPT TO:", 8) == 0) {
        /* Parse and store recipient address (strip angle brackets & whitespace) */
        if (session->rcpt_count < session->rcpt_capacity) {
            const char *raw = command + 8;
            while (*raw == ' ' || *raw == '\t') raw++;
            size_t len = strlen(raw);
            while (len > 0 && (raw[len-1] == '\r' || raw[len-1] == '\n' || raw[len-1] == ' ' || raw[len-1] == '\t')) len--;
            char *addr = strndup(raw, len);
            /* strip < > if present */
            if (addr[0] == '<') {
                char *end = strchr(addr, '>');
                if (end) {
                    size_t inner_len = end - (addr + 1);
                    char *inner = strndup(addr + 1, inner_len);
                    free(addr);
                    addr = inner;
                }
            }
            session->rcpt_to[session->rcpt_count++] = addr;
            send_response(session->client_fd, "250", "OK");
        } else {
            send_response(session->client_fd, "452", "Too many recipients");
        }
        session->state = LMTP_STATE_DATA;
    } else if (strncasecmp(command, "DATA", 4) == 0) {
        if (handle_data_phase(session) != 0) {
            send_response(session->client_fd, "451", "Error processing message");
        }
        // Reset for next message in session
        lmtp_session_cleanup(session);
        session->state = LMTP_STATE_MAIL;
    } else {
        send_response(session->client_fd, "500", "Command not recognized");
    }

    return 1;
}

static int handle_data_phase(lmtp_session_t* session) {
    send_response(session->client_fd, "354", "End data with <CR><LF>.<CR><LF>");

    /* Use mkstemp so we can hand file path to queue worker */
    char tmp_template[] = "/tmp/lightmail_lmtp_XXXXXX";
    int fd = mkstemp(tmp_template);
    if (fd < 0) {
        log_emit(LOG_LEVEL_ERROR, "lmtp", NULL, NULL, "Failed to create temporary file for mail data");
        return -1;
    }

    FILE *tmp_mail = fdopen(fd, "w+");
    if (!tmp_mail) {
        close(fd);
        unlink(tmp_template);
        log_emit(LOG_LEVEL_ERROR, "lmtp", NULL, NULL, "Failed to fdopen temporary file %s", tmp_template);
        return -1;
    }

    char buffer[LMTP_BUFFER_SIZE];
    ssize_t nread;
    long total_bytes = 0;

    while ((nread = read(session->client_fd, buffer, sizeof(buffer))) > 0) {
        total_bytes += nread;
        if (nread >= 3 && strncmp(&buffer[nread-3], ".\r\n", 3) == 0) {
            fwrite(buffer, 1, nread - 3, tmp_mail);
            break;
        }
        fwrite(buffer, 1, nread, tmp_mail);
    }

    fflush(tmp_mail);
    fclose(tmp_mail);

    /* Prepare per-recipient enqueue: for each valid RCPT, determine account and mailbox */
    int success_count = 0;
    for (size_t i = 0; i < session->rcpt_count; i++) {
        const char *rcpt = session->rcpt_to[i];
        if (!rcpt) continue;

        /* Lookup account by email */
        Account *acc = db_get_account_by_email(rcpt);
        if (!acc) {
            /* Unknown user: per-RCPT failure, log and continue */
            log_emit(LOG_LEVEL_WARN, "lmtp", NULL, NULL, "Unknown recipient %s", rcpt);
            /* According to LMTP, we'd respond per-recipient; here we log and skip */
            continue;
        }

        /* Ensure inbox exists for account */
        Mailbox *mb = db_ensure_inbox_exists(acc->id);
        if (!mb) {
            log_emit(LOG_LEVEL_ERROR, "lmtp", NULL, NULL, "Failed to find/create inbox for account %d", acc->id);
            db_free_account(acc);
            continue;
        }

        int assigned_uid = db_get_next_uid(mb->id);
        if (assigned_uid <= 0) assigned_uid = 1;

        /* Create a copy of the tmp file per-recipient so worker can unlink safely */
        char dst_template[] = "/tmp/lightmail_lmtp_copy_XXXXXX";
        int dst_fd = mkstemp(dst_template);
        if (dst_fd < 0) {
            log_emit(LOG_LEVEL_ERROR, "lmtp", NULL, NULL, "Failed to create temp file for recipient %s", rcpt);
            db_free_mailbox(mb);
            db_free_account(acc);
            continue;
        }
        FILE *src = fopen(tmp_template, "rb");
        if (!src) {
            close(dst_fd);
            unlink(dst_template);
            db_free_mailbox(mb);
            db_free_account(acc);
            continue;
        }
        FILE *dst = fdopen(dst_fd, "w+");
        if (!dst) {
            close(dst_fd);
            unlink(dst_template);
            fclose(src);
            db_free_mailbox(mb);
            db_free_account(acc);
            continue;
        }

        /* copy */
        char buf[4096];
        size_t r;
        rewind(src);
        while ((r = fread(buf, 1, sizeof(buf), src)) > 0) {
            fwrite(buf, 1, r, dst);
        }
        fflush(dst);
        fclose(src);
        fclose(dst);

        /* Enqueue copy */
        if (lmtp_queue_enqueue(dst_template, acc->id, mb->id, assigned_uid, (size_t)total_bytes) == 0) {
            success_count++;
        } else {
            log_emit(LOG_LEVEL_ERROR, "lmtp", NULL, NULL, "Queue full or error while enqueuing for recipient %s", rcpt);
            /* cleanup the failed attempt */
            unlink(dst_template);
        }

        db_free_mailbox(mb);
        db_free_account(acc);
    }

    /* remove original temp file */
    unlink(tmp_template);

    if (success_count > 0) {
        send_response(session->client_fd, "250", "OK, message accepted");
        return 0;
    } else {
        log_emit(LOG_LEVEL_ERROR, "lmtp", NULL, NULL, "No recipients accepted or queue full for all recipients");
        return -1;
    }
}

static void send_response(int fd, const char* code, const char* message) {
    char response[512];
    int len = snprintf(response, sizeof(response), "%s %s\r\n", code, message);
    if (len > 0) {
        log_emit(LOG_LEVEL_DEBUG, "lmtp", NULL, NULL, "S: %s", response);
        write(fd, response, len);
    }
}

static void lmtp_session_init(lmtp_session_t* session, int client_fd) {
    memset(session, 0, sizeof(lmtp_session_t));
    session->client_fd = client_fd;
    session->state = LMTP_STATE_GREETING;
    session->rcpt_capacity = 10;
    session->rcpt_to = malloc(sizeof(char*) * session->rcpt_capacity);
}

static void lmtp_session_cleanup(lmtp_session_t* session) {
    if (session->mail_from) {
        free(session->mail_from);
        session->mail_from = NULL;
    }
    if (session->rcpt_to) {
        for (size_t i = 0; i < session->rcpt_count; i++) {
            free(session->rcpt_to[i]);
        }
        // No need to free session->rcpt_to itself if it's a fixed-size array on the struct
        // but since we malloc'd it, we should free it.
    }
    session->rcpt_count = 0;
    // Don't free the main rcpt_to buffer, just reset the count to reuse it.
}