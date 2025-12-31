#include "db.h"
#include "password.h"

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

Account *db_get_account_by_username(const char *username, const char *domain) {
    MYSQL *conn = db_get_connection();
    if (!conn)
        return NULL;

    char query[1024];
    snprintf(query, sizeof(query),
             "SELECT a.id, a.domain_id, a.username, a.email, a.full_name, "
             "a.is_active, a.created_at, a.updated_at "
             "FROM accounts a JOIN domains d ON a.domain_id = d.id "
             "WHERE a.username = '%s' AND d.domain_name = '%s' AND a.is_active = 1",
             mysql_real_escape_string(conn, query + strlen(query) - 2, username, strlen(username)),
             mysql_real_escape_string(conn, query + strlen(query) - 2, domain, strlen(domain)));

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

    Account *account = malloc(sizeof(Account));
    account->id = atoi(row[0]);
    account->domain_id = atoi(row[1]);
    account->username = strdup(row[2]);
    account->email = strdup(row[3]);
    account->full_name = row[4] ? strdup(row[4]) : NULL;
    account->is_active = atoi(row[5]) == 1;
    account->created_at = (time_t)atol(row[6]);
    account->updated_at = (time_t)atol(row[7]);

    mysql_free_result(result);
    db_release_connection(conn);

    return account;
}

Account *db_get_account_by_email(const char *email) {
    MYSQL *conn = db_get_connection();
    if (!conn)
        return NULL;

    char query[1024];
    snprintf(query, sizeof(query),
             "SELECT id, domain_id, username, email, full_name, "
             "is_active, created_at, updated_at "
             "FROM accounts WHERE email = '%s' AND is_active = 1",
             mysql_real_escape_string(conn, query + strlen(query) - 2, email, strlen(email)));

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

    Account *account = malloc(sizeof(Account));
    account->id = atoi(row[0]);
    account->domain_id = atoi(row[1]);
    account->username = strdup(row[2]);
    account->email = strdup(row[3]);
    account->full_name = row[4] ? strdup(row[4]) : NULL;
    account->is_active = atoi(row[5]) == 1;
    account->created_at = (time_t)atol(row[6]);
    account->updated_at = (time_t)atol(row[7]);

    mysql_free_result(result);
    db_release_connection(conn);

    return account;
}

Account *db_create_account(const char *username, const char *domain, const char *password, const char *email, const char *full_name) {
    MYSQL *conn = db_get_connection();
    if (!conn)
        return NULL;

    // Get domain ID
    char domain_query[512];
    snprintf(domain_query, sizeof(domain_query),
             "SELECT id FROM domains WHERE domain_name = '%s'",
             mysql_real_escape_string(conn, domain_query + strlen(domain_query) - 2, domain, strlen(domain)));

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
    char password_hash = create_password(password);
    if (!password_hash) {
        db_release_connection(conn);
        return NULL;
    }

    // Insert account
    char insert_query[2048];
    snprintf(insert_query, sizeof(insert_query),
             "INSERT INTO accounts (domain_id, username, email, full_name, password_hash, is_active, created_at, updated_at) "
             "VALUES (%d, '%s', '%s', '%s', '%s', 1, NOW(), NOW())",
             domain_id,
             mysql_real_escape_string(conn, insert_query + strlen(insert_query) - 2, username, strlen(username)),
             mysql_real_escape_string(conn, insert_query + strlen(insert_query) - 2, email, strlen(email)),
             mysql_real_escape_string(conn, insert_query + strlen(insert_query) - 2, full_name ? full_name : "", full_name ? strlen(full_name) : 0),
             mysql_real_escape_string(conn, insert_query + strlen(insert_query) - 2, password_hash, strlen(password_hash)));

    if (!db_execute_query(conn, insert_query)) {
        db_release_connection(conn);
        return NULL;
    }

    int account_id = (int)mysql_insert_id(conn);
    db_release_connection(conn);

    return db_get_account_by_username(username, domain);
}