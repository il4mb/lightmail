#include "db.h"
#include "conf.h"
#include "password.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <mysql/mysql.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static ConnectionPool connection_pool;

// Initialize database connection pool
bool db_init(void) {

    const ServerConfig *cfg = get_config();

    pthread_mutex_init(&connection_pool.lock, NULL);
    connection_pool.count = 0;
    connection_pool.max = cfg->db_pool_size;
    
    for (int i = 0; i < connection_pool.max; i++) {
        MYSQL *conn = mysql_init(NULL);
        if (!conn) {
            fprintf(stderr, "Failed to initialize MySQL connection\n");
            return false;
        }
        
        // Set connection options
        mysql_options(conn, MYSQL_SET_CHARSET_NAME, "utf8mb4");
        mysql_options(conn, MYSQL_INIT_COMMAND, "SET NAMES utf8mb4");
        
        // Connect to database
        if (!mysql_real_connect(conn, cfg->db_host, cfg->db_user, cfg->db_password, cfg->db_name, cfg->db_port, NULL, 0)) {
            fprintf(stderr, "Failed to connect to database: %s\n", mysql_error(conn));
            mysql_close(conn);
            return false;
        }
        
        connection_pool.connections[connection_pool.count++] = conn;
    }
    
    printf("Database pool initialized with %d connections\n", connection_pool.count);
    return true;
}

// Get connection from pool
MYSQL* db_get_connection(void) {
    
    const ServerConfig *cfg = get_config();
    pthread_mutex_lock(&connection_pool.lock);
    
    if (connection_pool.count == 0) {
        // Create new connection if pool is empty
        MYSQL *conn = mysql_init(NULL);
        if (conn && mysql_real_connect(conn, cfg->db_host, cfg->db_user, cfg->db_password, cfg->db_name, cfg->db_port, NULL, 0)) {
            pthread_mutex_unlock(&connection_pool.lock);
            return conn;
        }
        pthread_mutex_unlock(&connection_pool.lock);
        return NULL;
    }
    
    MYSQL *conn = connection_pool.connections[--connection_pool.count];
    pthread_mutex_unlock(&connection_pool.lock);
    return conn;
}

// Release connection back to pool
void db_release_connection(MYSQL *conn) {
    pthread_mutex_lock(&connection_pool.lock);
    
    if (connection_pool.count < connection_pool.max) {
        connection_pool.connections[connection_pool.count++] = conn;
    } else {
        mysql_close(conn);
    }
    
    pthread_mutex_unlock(&connection_pool.lock);
}

// Cleanup database pool
void db_cleanup(void) {
    pthread_mutex_lock(&connection_pool.lock);
    
    for (int i = 0; i < connection_pool.count; i++) {
        mysql_close(connection_pool.connections[i]);
    }
    
    connection_pool.count = 0;
    pthread_mutex_unlock(&connection_pool.lock);
    pthread_mutex_destroy(&connection_pool.lock);
}

// Get account by username and domain
Account* db_get_account_by_username(const char *username, const char *domain) {
    MYSQL *conn = db_get_connection();
    if (!conn) return NULL;
    
    char query[1024];
    snprintf(query, sizeof(query),
        "SELECT a.id, a.domain_id, a.username, a.email, a.full_name, "
        "a.password_hash, a.is_active, a.created_at, a.updated_at "
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
    // Note: password_hash is not stored in Account struct for security
    
    mysql_free_result(result);
    db_release_connection(conn);
    
    return account;
}

// Verify password
bool db_verify_password(Account *account, const char *password) {
    MYSQL *conn = db_get_connection();
    if (!conn) return false;
    
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

// Get mailbox by name for account
Mailbox* db_get_mailbox(int account_id, const char *name) {
    MYSQL *conn = db_get_connection();
    if (!conn) return NULL;
    
    char query[1024];
    snprintf(query, sizeof(query),
        "SELECT id, account_id, name, flags, permanent_flags, "
        "uid_validity, uid_next, total_messages, unseen_messages, "
        "recent_messages, is_subscribed, created_at, updated_at "
        "FROM mailboxes WHERE account_id = %d AND name = '%s'",
        account_id, mysql_real_escape_string(conn, query + strlen(query) - 2, 
                                           name, strlen(name)));
    
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
    
    Mailbox *mailbox = malloc(sizeof(Mailbox));
    mailbox->id = atoi(row[0]);
    mailbox->account_id = atoi(row[1]);
    mailbox->name = strdup(row[2]);
    mailbox->flags = row[3] ? strdup(row[3]) : strdup("");
    mailbox->permanent_flags = row[4] ? strdup(row[4]) : strdup("");
    mailbox->uid_validity = atoi(row[5]);
    mailbox->uid_next = atoi(row[6]);
    mailbox->total_messages = atoi(row[7]);
    mailbox->unseen_messages = atoi(row[8]);
    mailbox->recent_messages = atoi(row[9]);
    mailbox->is_subscribed = atoi(row[10]) == 1;
    
    mysql_free_result(result);
    db_release_connection(conn);
    
    return mailbox;
}

// Get all mailboxes for account
Mailbox** db_get_mailboxes(int account_id, int *count) {
    MYSQL *conn = db_get_connection();
    if (!conn) {
        *count = 0;
        return NULL;
    }
    
    char query[512];
    snprintf(query, sizeof(query),
        "SELECT id, name, total_messages, unseen_messages, recent_messages "
        "FROM mailboxes WHERE account_id = %d AND is_subscribed = 1 "
        "ORDER BY name",
        account_id);
    
    MYSQL_RES *result = db_execute_query_result(conn, query);
    if (!result) {
        db_release_connection(conn);
        *count = 0;
        return NULL;
    }
    
    int num_rows = mysql_num_rows(result);
    Mailbox **mailboxes = malloc(sizeof(Mailbox*) * num_rows);
    
    int i = 0;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        Mailbox *mailbox = malloc(sizeof(Mailbox));
        mailbox->id = atoi(row[0]);
        mailbox->name = strdup(row[1]);
        mailbox->total_messages = atoi(row[2]);
        mailbox->unseen_messages = atoi(row[3]);
        mailbox->recent_messages = atoi(row[4]);
        mailbox->account_id = account_id;
        mailboxes[i++] = mailbox;
    }
    
    *count = i;
    mysql_free_result(result);
    db_release_connection(conn);
    
    return mailboxes;
}

// Store message in database
bool db_store_message(Message *message) {
    MYSQL *conn = db_get_connection();
    if (!conn) return false;
    
    char query[4096];
    snprintf(query, sizeof(query),
        "INSERT INTO messages (mailbox_id, uid, internal_date, flags, size, "
        "envelope_from, envelope_to, envelope_subject, envelope_message_id, "
        "body_s3_key, body_size, mime_type, encoding) "
        "VALUES (%d, %d, FROM_UNIXTIME(%ld), '%s', %d, '%s', '%s', '%s', '%s', "
        "'%s', %d, '%s', '%s')",
        message->mailbox_id,
        message->uid,
        (long)message->internal_date,
        mysql_real_escape_string(conn, query + strlen(query) - 2, 
                               message->flags, strlen(message->flags)),
        message->size,
        mysql_real_escape_string(conn, query + strlen(query) - 2, 
                               message->envelope_from, strlen(message->envelope_from)),
        mysql_real_escape_string(conn, query + strlen(query) - 2, 
                               message->envelope_to, strlen(message->envelope_to)),
        mysql_real_escape_string(conn, query + strlen(query) - 2, 
                               message->envelope_subject, strlen(message->envelope_subject)),
        message->envelope_message_id ? 
            mysql_real_escape_string(conn, query + strlen(query) - 2, 
                                   message->envelope_message_id, 
                                   strlen(message->envelope_message_id)) : "",
        mysql_real_escape_string(conn, query + strlen(query) - 2, 
                               message->body_s3_key, strlen(message->body_s3_key)),
        message->body_size,
        mysql_real_escape_string(conn, query + strlen(query) - 2, 
                               message->mime_type, strlen(message->mime_type)),
        mysql_real_escape_string(conn, query + strlen(query) - 2, 
                               message->encoding, strlen(message->encoding)));
    
    bool success = db_execute_query(conn, query);
    
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

// Get next UID for mailbox
int db_get_next_uid(int mailbox_id) {
    MYSQL *conn = db_get_connection();
    if (!conn) return -1;
    
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
    int uid_next = row ? atoi(row[0]) : -1;
    
    mysql_free_result(result);
    db_release_connection(conn);
    
    return uid_next;
}

// Execute query without result
bool db_execute_query(MYSQL *conn, const char *query) {
    if (mysql_query(conn, query) != 0) {
        fprintf(stderr, "Query failed: %s\n", mysql_error(conn));
        return false;
    }
    return true;
}

// Execute query and return result
MYSQL_RES* db_execute_query_result(MYSQL *conn, const char *query) {
    if (mysql_query(conn, query) != 0) {
        fprintf(stderr, "Query failed: %s\n", mysql_error(conn));
        return NULL;
    }
    return mysql_store_result(conn);
}

// Free result
void db_free_result(MYSQL_RES *result) {
    if (result) mysql_free_result(result);
}