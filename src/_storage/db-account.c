#include "db.h"
#include "parser.h"
#include "password.h"
#include <stdio.h>
#include <string.h>

// Verify password
bool db_verify_password(Account *account, const char *password) {
    MYSQL *conn = db_get_connection();
    if (!conn)
        return false;

    char query[512];
    snprintf(query, sizeof(query), "SELECT password_hash FROM accounts WHERE id = %d", account->id);

    MYSQL_RES *result = db_execute_query_result(conn, query);
    if (!result) {
        db_release_connection(conn);
        return false;
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    if (!row || !row[0]) {
        mysql_free_result(result);
        db_release_connection(conn);
        return false;
    }

    // Verify bcrypt hash
    bool verified = (verify_password(password, row[0]) == 0);

    mysql_free_result(result);
    db_release_connection(conn);

    return verified;
}

/**
 * Get account by username and domain
 * @param username The username test@example.com
 * @return Pointer to Account struct or NULL if not found
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
Account *db_get_account_by_username(const char *username) {

    MYSQL *conn = db_get_connection();
    if (!conn)
        return NULL;

    char query[4096];
    char esc_username[2048] = {0};
    mysql_real_escape_string(conn, esc_username, username ? username : "", username ? (unsigned long)strlen(username) : 0);
    snprintf(query, sizeof(query),
             "SELECT a.id, a.domain_id, a.username, a.full_name, "
             "a.is_active, a.created_at, a.updated_at "
             "FROM accounts a JOIN domains d ON a.domain_id = d.id "
             "WHERE a.is_active = '%d' AND a.username = '%s'",
             1, esc_username);

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

    Account *account = malloc(sizeof(Account));
    account->id = atoi(row[0]);
    account->domain_id = atoi(row[1]);
    account->username = strdup(row[2]);
    account->full_name = row[3] ? strdup(row[3]) : NULL;
    account->is_active = atoi(row[4]) == 1;
    account->created_at = (time_t)atol(row[5]);
    account->updated_at = (time_t)atol(row[6]);

    mysql_free_result(result);
    db_release_connection(conn);

    return account;
}

Account *db_create_account(const char *username, const char *password, const char *full_name) {
    MYSQL *conn = db_get_connection();
    if (!conn)
        return NULL;

    // get domain from username
    const char *domain = get_domain_from_email(username);
    if (!domain) {
        db_release_connection(conn);
        return NULL;
    }

    // Get domain ID
    char domain_query[1024];
    char esc_domain[1024] = {0};
    mysql_real_escape_string(conn, esc_domain, domain ? domain : "", domain ? (unsigned long)strlen(domain) : 0);
    snprintf(domain_query, sizeof(domain_query), "SELECT id FROM domains WHERE domain_name = '%s'", esc_domain);

    MYSQL_RES *domain_result = db_execute_query_result(conn, domain_query);
    if (!domain_result) {
        db_release_connection(conn);
        return NULL;
    }

    MYSQL_ROW domain_row = mysql_fetch_row(domain_result);
    if (!domain_row) {
        mysql_free_result(domain_result);
        db_release_connection(conn);
        return NULL;
    }

    int domain_id = atoi(domain_row[0]);
    mysql_free_result(domain_result);

    // Hash password
    char *password_hash = create_password(password);
    if (!password_hash) {
        db_release_connection(conn);
        return NULL;
    }

    // Insert account (no email column needed - email derived from username@domain)
    char insert_query[8192];
    char esc_username[2048] = {0}, esc_full_name[2048] = {0}, esc_password_hash[2048] = {0};
    mysql_real_escape_string(conn, esc_username, username ? username : "", username ? (unsigned long)strlen(username) : 0);
    mysql_real_escape_string(conn, esc_full_name, full_name ? full_name : "", full_name ? (unsigned long)strlen(full_name) : 0);
    mysql_real_escape_string(conn, esc_password_hash, password_hash, strlen(password_hash));

    snprintf(insert_query, sizeof(insert_query),
             "INSERT INTO accounts (domain_id, username, full_name, password_hash, is_active, created_at, updated_at) "
             "VALUES (%d, '%s', '%s', '%s', 1, NOW(), NOW())",
             domain_id, esc_username, esc_full_name, esc_password_hash);

    if (!db_execute_query(conn, insert_query)) {
        free(password_hash);
        db_release_connection(conn);
        return NULL;
    }

    free(password_hash);

    db_release_connection(conn);

    return db_get_account_by_username(username);
}

#pragma GCC diagnostic pop

/* Free Account and its fields */
void db_free_account(Account *a) {
    if (!a)
        return;
    free(a->username);
    if (a->full_name)
        free(a->full_name);
    free(a);
}
