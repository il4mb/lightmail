#ifndef DB_H
#define DB_H

#include "password.h"
#include <mysql/mysql.h>
#include <stdbool.h>
#include <time.h>
#include <bits/pthreadtypes.h>

typedef struct {
    char *host;
    char *user;
    char *password;
    char *name;
    char *socket;
    int port;
    int pool_size;
} DBConfig;

// Connection pool structure
typedef struct {
    MYSQL *connections[20];
    int count;
    int max;
    pthread_mutex_t lock;
} ConnectionPool;

// Database structures
typedef struct {
    int id;
    char *domain_name;
    int quota_mb;
    int quota_used_mb;
    time_t created_at;
    time_t updated_at;
} Domain;

typedef struct {
    int id;
    int domain_id;
    char *username;
    char *full_name;
    bool is_active;
    int quota_mb;
    int quota_used_mb;
    time_t created_at;
    time_t updated_at;
} Account;

typedef struct {
    int id;
    int account_id;
    char *name;
    char *flags;
    char *permanent_flags;
    int uid_validity;
    int uid_next;
    int total_messages;
    int unseen_messages;
    int recent_messages;
    bool is_subscribed;
    time_t created_at;
    time_t updated_at;
} Mailbox;

typedef struct {
    int id;
    int mailbox_id;
    int uid;
    time_t internal_date;
    char *flags;
    int size;
    char *envelope_from;
    char *envelope_to;
    char *envelope_subject;
    char *envelope_message_id;
    char *body_s3_key;
    int body_size;
    char *mime_type;
    char *encoding;
    time_t created_at;
    time_t updated_at;
} Message;


// Database functions
int db_init(void);
void db_cleanup(void);
MYSQL* db_get_connection(void);
void db_release_connection(MYSQL *conn);

// Account functions
Account* db_get_account_by_username(const char *username);
bool db_verify_password(Account *account, const char *password);
Account* db_create_account(const char *username, const char *password, const char *full_name);

// Mailbox functions
Mailbox* db_get_mailbox(int account_id, const char *name);
Mailbox** db_get_mailboxes(int account_id, int *count);
bool db_create_mailbox(int account_id, const char *name, const char *flags);
bool db_delete_mailbox(int mailbox_id);
bool db_update_mailbox_stats(int mailbox_id);
Mailbox* db_ensure_inbox_exists(int account_id);

// Message functions
Message* db_get_message(int mailbox_id, int uid);
Message** db_get_messages(int mailbox_id, int offset, int limit, int *count);
bool db_store_message(Message *message);
bool db_update_message_flags(int message_id, const char *flags);
bool db_delete_message(int message_id);
int db_get_next_uid(int mailbox_id);
int db_allocate_uid(int mailbox_id); /* Atomically increment uid_next and return assigned uid, or -1 on error */

/* Convenience free helpers */
void db_free_message(Message *m);
void db_free_mailbox(Mailbox *m);
void db_free_account(Account *a);

// Domain functions
Domain* db_get_domain(const char *domain_name);
bool db_domain_exists(const char *domain_name);

// Utility functions
bool db_execute_query(MYSQL *conn, const char *query);
MYSQL_RES* db_execute_query_result(MYSQL *conn, const char *query);
void db_free_result(MYSQL_RES *result);

#endif