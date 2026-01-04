#include "db.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static int xasprintf(char **strp, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int len = vsnprintf(NULL, 0, fmt, ap);
    if (len < 0) { va_end(ap); va_end(ap2); return -1; }
    char *buf = malloc(len + 1);
    if (!buf) { va_end(ap); va_end(ap2); return -1; }
    vsnprintf(buf, len + 1, fmt, ap2);
    va_end(ap);
    va_end(ap2);
    *strp = buf;
    return len;
}

// Message functions
Message *db_get_message(int mailbox_id, int uid) {
    MYSQL *conn = db_get_connection();
    if (!conn)
        return NULL;

    char query[512];
    snprintf(query, sizeof(query),
             "SELECT id, mailbox_id, uid, internal_date, flags, size, "
             "envelope_from, envelope_to, envelope_subject, envelope_message_id, "
             "body_s3_key, body_size, mime_type, encoding, created_at, updated_at "
             "FROM messages WHERE mailbox_id = %d AND uid = %d",
             mailbox_id, uid);

    MYSQL_RES *result = db_execute_query_result(conn, query);
    if (!result) {
        db_release_connection(conn);
        return NULL;
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    if (!row) {
        mysql_free_result(result);
        db_release_connection(conn);
        return NULL;
    }

    Message *message = malloc(sizeof(Message));
    message->id = atoi(row[0]);
    message->mailbox_id = atoi(row[1]);
    message->uid = atoi(row[2]);
    message->internal_date = (time_t)atol(row[3]);
    message->flags = strdup(row[4]);
    message->size = atoi(row[5]);
    message->envelope_from = strdup(row[6]);
    message->envelope_to = strdup(row[7]);
    message->envelope_subject = strdup(row[8]);
    message->envelope_message_id = strdup(row[9]);
    message->body_s3_key = strdup(row[10]);
    message->body_size = atoi(row[11]);
    message->mime_type = strdup(row[12]);
    message->encoding = strdup(row[13]);
    message->created_at = (time_t)atol(row[14]);
    message->updated_at = (time_t)atol(row[15]);

    mysql_free_result(result);
    db_release_connection(conn);

    return message;
}

Message **db_get_messages(int mailbox_id, int offset, int limit, int *count) {
    MYSQL *conn = db_get_connection();
    if (!conn) {
        *count = 0;
        return NULL;
    }

    char query[512];
    snprintf(query, sizeof(query),
             "SELECT id, mailbox_id, uid, internal_date, flags, size, "
             "envelope_from, envelope_to, envelope_subject, envelope_message_id, "
             "body_s3_key, body_size, mime_type, encoding, created_at, updated_at "
             "FROM messages WHERE mailbox_id = %d "
             "ORDER BY uid ASC LIMIT %d OFFSET %d",
             mailbox_id, limit, offset);

    MYSQL_RES *result = db_execute_query_result(conn, query);
    if (!result) {
        db_release_connection(conn);
        *count = 0;
        return NULL;
    }

    int num_rows = mysql_num_rows(result);
    Message **messages = malloc(sizeof(Message *) * num_rows);

    int i = 0;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        Message *message = malloc(sizeof(Message));
        message->id = atoi(row[0]);
        message->mailbox_id = atoi(row[1]);
        message->uid = atoi(row[2]);
        message->internal_date = (time_t)atol(row[3]);
        message->flags = strdup(row[4]);
        message->size = atoi(row[5]);
        message->envelope_from = strdup(row[6]);
        message->envelope_to = strdup(row[7]);
        message->envelope_subject = strdup(row[8]);
        message->envelope_message_id = strdup(row[9]);
        message->body_s3_key = strdup(row[10]);
        message->body_size = atoi(row[11]);
        message->mime_type = strdup(row[12]);
        message->encoding = strdup(row[13]);
        message->created_at = (time_t)atol(row[14]);
        message->updated_at = (time_t)atol(row[15]);
        messages[i++] = message;
    }

    *count = i;
    mysql_free_result(result);
    db_release_connection(conn);

    return messages;
}

bool db_store_message(Message *message) {
    MYSQL *conn = db_get_connection();
    if (!conn)
        return false;

    char *query = NULL;

    /* Escape all variable inputs into local buffers first */
    char esc_flags[1024] = {0};
    char esc_envelope_from[1024] = {0};
    char esc_envelope_to[1024] = {0};
    char esc_envelope_subject[1024] = {0};
    char esc_envelope_message_id[1024] = {0};
    char esc_body_s3_key[1024] = {0};
    char esc_mime_type[512] = {0};
    char esc_encoding[256] = {0};

    if (message->flags) mysql_real_escape_string(conn, esc_flags, message->flags, strlen(message->flags));
    if (message->envelope_from) mysql_real_escape_string(conn, esc_envelope_from, message->envelope_from, strlen(message->envelope_from));
    if (message->envelope_to) mysql_real_escape_string(conn, esc_envelope_to, message->envelope_to, strlen(message->envelope_to));
    if (message->envelope_subject) mysql_real_escape_string(conn, esc_envelope_subject, message->envelope_subject, strlen(message->envelope_subject));
    if (message->envelope_message_id) mysql_real_escape_string(conn, esc_envelope_message_id, message->envelope_message_id, strlen(message->envelope_message_id));
    if (message->body_s3_key) mysql_real_escape_string(conn, esc_body_s3_key, message->body_s3_key, strlen(message->body_s3_key));
    if (message->mime_type) mysql_real_escape_string(conn, esc_mime_type, message->mime_type, strlen(message->mime_type));
    if (message->encoding) mysql_real_escape_string(conn, esc_encoding, message->encoding, strlen(message->encoding));

    if (xasprintf(&query,
             "INSERT INTO messages (mailbox_id, uid, internal_date, flags, size, "
             "envelope_from, envelope_to, envelope_subject, envelope_message_id, "
             "body_s3_key, body_size, mime_type, encoding) "
             "VALUES (%d, %d, FROM_UNIXTIME(%ld), '%s', %d, '%s', '%s', '%s', '%s', "
             "'%s', %d, '%s', '%s')",
             message->mailbox_id,
             message->uid,
             (long)message->internal_date,
             esc_flags[0] ? esc_flags : "",
             message->size,
             esc_envelope_from[0] ? esc_envelope_from : "",
             esc_envelope_to[0] ? esc_envelope_to : "",
             esc_envelope_subject[0] ? esc_envelope_subject : "",
             esc_envelope_message_id[0] ? esc_envelope_message_id : "",
             esc_body_s3_key[0] ? esc_body_s3_key : "",
             message->body_size,
             esc_mime_type[0] ? esc_mime_type : "",
             esc_encoding[0] ? esc_encoding : "") < 0) {
        db_release_connection(conn);
        return false;
    }

    bool success = db_execute_query(conn, query);
    free(query);

    if (success) {
        // Update mailbox stats
        char update_query[512];
        snprintf(update_query, sizeof(update_query),
                 "UPDATE mailboxes SET total_messages = total_messages + 1, "
                 "uid_next = uid_next + 1, recent_messages = recent_messages + 1 "
                 "WHERE id = %d",
                 message->mailbox_id);
        db_execute_query(conn, update_query);
    }
    db_release_connection(conn);

    return success;
}

bool db_update_message_flags(int message_id, const char *flags) {
    MYSQL *conn = db_get_connection();
    if (!conn)
        return false;

    char *query = NULL;
    char esc_flags[1024] = {0};
    if (flags) mysql_real_escape_string(conn, esc_flags, flags, strlen(flags));

    if (xasprintf(&query,
             "UPDATE messages SET flags = '%s', updated_at = NOW() "
             "WHERE id = %d",
             esc_flags[0] ? esc_flags : "",
             message_id) < 0) {
        db_release_connection(conn);
        return false;
    }

    bool success = db_execute_query(conn, query);
    free(query);
    db_release_connection(conn);

    return success;
}

bool db_delete_message(int message_id) {
    MYSQL *conn = db_get_connection();
    if (!conn)
        return false;

    char query[256];
    snprintf(query, sizeof(query),
             "DELETE FROM messages WHERE id = %d",
             message_id);

    bool success = db_execute_query(conn, query);
    db_release_connection(conn);

    return success;
}

int db_get_next_uid(int mailbox_id) {
    MYSQL *conn = db_get_connection();
    if (!conn)
        return -1;

    char query[256];
    snprintf(query, sizeof(query),
             "SELECT uid_next FROM mailboxes WHERE id = %d",
             mailbox_id);

    MYSQL_RES *result = db_execute_query_result(conn, query);
    if (!result) {
        db_release_connection(conn);
        return -1;
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    if (!row) {
        mysql_free_result(result);
        db_release_connection(conn);
        return -1;
    }

    int uid_next = atoi(row[0]);

    mysql_free_result(result);
    db_release_connection(conn);

    return uid_next;
}

/* Atomically increment uid_next and return the assigned uid (previous value). */
int db_allocate_uid(int mailbox_id) {
    MYSQL *conn = db_get_connection();
    if (!conn)
        return -1;

    char query[256];
    snprintf(query, sizeof(query), "UPDATE mailboxes SET uid_next = uid_next + 1 WHERE id = %d", mailbox_id);
    if (!db_execute_query(conn, query)) {
        db_release_connection(conn);
        return -1;
    }

    snprintf(query, sizeof(query), "SELECT uid_next - 1 FROM mailboxes WHERE id = %d", mailbox_id);
    MYSQL_RES *res = db_execute_query_result(conn, query);
    if (!res) {
        db_release_connection(conn);
        return -1;
    }

    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) {
        mysql_free_result(res);
        db_release_connection(conn);
        return -1;
    }

    int assigned = atoi(row[0]);
    mysql_free_result(res);
    db_release_connection(conn);
    return assigned;
}

/* Free a Message and its allocated fields */
void db_free_message(Message *m) {
    if (!m)
        return;
    free(m->flags);
    free(m->envelope_from);
    free(m->envelope_to);
    free(m->envelope_subject);
    free(m->envelope_message_id);
    free(m->body_s3_key);
    free(m->mime_type);
    free(m->encoding);
    free(m);
}