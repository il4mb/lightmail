#include "db.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Mailbox functions
Mailbox *db_get_mailbox(int account_id, const char *name) {
    MYSQL *conn = db_get_connection();
    if (!conn) return NULL;

    char query[1024];
    char esc_name[512] = {0};
    mysql_real_escape_string(conn, esc_name, name ? name : "", name ? (unsigned long)strlen(name) : 0);
    snprintf(query, sizeof(query),
        "SELECT id, account_id, name, flags, permanent_flags, "
        "uid_validity, uid_next, total_messages, unseen_messages, "
        "recent_messages, is_subscribed, created_at, updated_at "
        "FROM mailboxes WHERE account_id = %d AND name = '%s'",
        account_id,
        esc_name);

    /* Debug: persist constructed query */
    FILE *dq = fopen("/tmp/db-query.log", "a");
    if (dq) {
        fprintf(dq, "QUERY: %s\n", query);
        fclose(dq);
    }

    MYSQL_RES *result = db_execute_query_result(conn, query);
    if (!result) {
        /* Debug: log mysql error */
        FILE *de = fopen("/tmp/db-query.log", "a");
        if (de) {
            fprintf(de, "QUERY ERROR: %s\n", mysql_error(conn));
            fclose(de);
        }
        db_release_connection(conn);
        return NULL;
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    if (!row) {
        mysql_free_result(result);
        db_release_connection(conn);
        return NULL;
    }

    Mailbox *mailbox = malloc(sizeof(Mailbox));
    mailbox->id = atoi(row[0]);
    mailbox->account_id = atoi(row[1]);
    mailbox->name = strdup(row[2]);
    mailbox->flags = strdup(row[3]);
    mailbox->permanent_flags = strdup(row[4]);
    mailbox->uid_validity = atoi(row[5]);
    mailbox->uid_next = atoi(row[6]);
    mailbox->total_messages = atoi(row[7]);
    mailbox->unseen_messages = atoi(row[8]);
    mailbox->recent_messages = atoi(row[9]);
    mailbox->is_subscribed = atoi(row[10]) == 1;
    mailbox->created_at = (time_t)atol(row[11]);
    mailbox->updated_at = (time_t)atol(row[12]);

    mysql_free_result(result);
    db_release_connection(conn);

    return mailbox;
}

Mailbox **db_get_mailboxes(int account_id, int *count) {
    MYSQL *conn = db_get_connection();
    if (!conn) {
        *count = 0;
        return NULL;
    }

    char query[1024];
    snprintf(query, sizeof(query),
        "SELECT id, account_id, name, flags, permanent_flags, "
        "uid_validity, uid_next, total_messages, unseen_messages, "
        "recent_messages, is_subscribed, created_at, updated_at "
        "FROM mailboxes WHERE account_id = %d",
        account_id);

    /* Debug: persist constructed query */
    FILE *dq = fopen("/tmp/db-query.log", "a");
    if (dq) {
        fprintf(dq, "QUERY: %s\n", query);
        fclose(dq);
    }

    MYSQL_RES *result = db_execute_query_result(conn, query);
    if (!result) {
        /* Debug: log mysql error */
        FILE *de = fopen("/tmp/db-query.log", "a");
        if (de) {
            fprintf(de, "QUERY ERROR: %s\n", mysql_error(conn));
            fclose(de);
        }
        db_release_connection(conn);
        *count = 0;
        return NULL;
    }

    int num_rows = mysql_num_rows(result);
    Mailbox **mailboxes = malloc(sizeof(Mailbox *) * num_rows);

    int i = 0;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        Mailbox *mailbox = malloc(sizeof(Mailbox));
        mailbox->id = atoi(row[0]);
        mailbox->account_id = atoi(row[1]);
        mailbox->name = strdup(row[2]);
        mailbox->flags = strdup(row[3]);
        mailbox->permanent_flags = strdup(row[4]);
        mailbox->uid_validity = atoi(row[5]);
        mailbox->uid_next = atoi(row[6]);
        mailbox->total_messages = atoi(row[7]);
        mailbox->unseen_messages = atoi(row[8]);
        mailbox->recent_messages = atoi(row[9]);
        mailbox->is_subscribed = atoi(row[10]) == 1;
        mailbox->created_at = (time_t)atol(row[11]);
        mailbox->updated_at = (time_t)atol(row[12]);
        mailboxes[i++] = mailbox;
    }

    *count = i;
    mysql_free_result(result);
    db_release_connection(conn);

    return mailboxes;
}

/* Free a Mailbox and its allocated fields */
void db_free_mailbox(Mailbox *m) {
    if (!m) return;
    free(m->name);
    free(m->flags);
    free(m->permanent_flags);
    free(m);
}   

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
bool db_create_mailbox(int account_id, const char *name, const char *flags) {
    MYSQL *conn = db_get_connection();
    if (!conn) return false;

    char query[1024];
    char esc_name[512] = {0}, esc_flags[512] = {0};
    mysql_real_escape_string(conn, esc_name, name ? name : "", name ? (unsigned long)strlen(name) : 0);
    mysql_real_escape_string(conn, esc_flags, flags ? flags : "", flags ? (unsigned long)strlen(flags) : 0);

    snprintf(query, sizeof(query),
        "INSERT INTO mailboxes (account_id, name, flags, permanent_flags, "
        "uid_validity, uid_next, total_messages, unseen_messages, "
        "recent_messages, is_subscribed, created_at, updated_at) "
        "VALUES (%d, '%s', '%s', '%s', %d, %d, 0, 0, 0, 1, NOW(), NOW())",
        account_id,
        esc_name,
        esc_flags,
        esc_flags, /* Permanent flags same as initial flags */
        rand() % 100000 + 1, /* Random UID validity */
        1); /* Initial UID next */

    bool success = db_execute_query(conn, query);
    db_release_connection(conn);

#pragma GCC diagnostic pop

    return success;
}

bool db_delete_mailbox(int mailbox_id) {
    MYSQL *conn = db_get_connection();
    if (!conn) return false;

    char query[256];
    snprintf(query, sizeof(query),
        "DELETE FROM mailboxes WHERE id = %d",
        mailbox_id);

    bool success = db_execute_query(conn, query);
    db_release_connection(conn);

    return success;
}

bool db_update_mailbox_stats(int mailbox_id) {
    MYSQL *conn = db_get_connection();
    if (!conn) return false;

    char query[512];
    snprintf(query, sizeof(query),
        "UPDATE mailboxes SET total_messages = "
        "(SELECT COUNT(*) FROM messages WHERE mailbox_id = %d), "
        "unseen_messages = "
        "(SELECT COUNT(*) FROM messages WHERE mailbox_id = %d AND "
        "FIND_IN_SET('\\Seen', flags) = 0), "
        "recent_messages = "
        "(SELECT COUNT(*) FROM messages WHERE mailbox_id = %d AND "
        "internal_date >= NOW() - INTERVAL 1 DAY), "
        "updated_at = NOW() "
        "WHERE id = %d",
        mailbox_id, mailbox_id, mailbox_id, mailbox_id);

    bool success = db_execute_query(conn, query);
    db_release_connection(conn);

    return success;
}

Mailbox *db_ensure_inbox_exists(int account_id) {
    Mailbox *mailbox = db_get_mailbox(account_id, "INBOX");
    if (mailbox) {
        return mailbox;
    }

    if (db_create_mailbox(account_id, "INBOX", "\\Answered \\Flagged \\Deleted \\Seen \\Draft")) {
        return db_get_mailbox(account_id, "INBOX");
    }

    return NULL;
}