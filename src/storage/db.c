#include "db.h"
#include "lightmail.h"
#include "password.h"
#include "metrics.h"
#include <time.h>
#include <mysql/mysql.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void config_callback(const char *key, const char *value, void *ctx) {
    DBConfig *db_config = (DBConfig *)ctx;
    if (strcmp(key, "host") == 0) {
        db_config->host = strdup(value);
    } else if (strcmp(key, "user") == 0) {
        db_config->user = strdup(value);
    } else if (strcmp(key, "password") == 0) {
        db_config->password = strdup(value);
    } else if (strcmp(key, "name") == 0) {
        db_config->name = strdup(value);
    } else if (strcmp(key, "database") == 0) {
        db_config->name = strdup(value);
    } else if (strcmp(key, "socket") == 0) {
        db_config->socket = strdup(value);
    } else if (strcmp(key, "port") == 0) {
        db_config->port = atoi(value);
    } else if (strcmp(key, "pool_size") == 0) {
        db_config->pool_size = atoi(value);
    }
}

static DBConfig cfg = {
    .host = NULL,
    .user = NULL,
    .password = NULL,
    .name = NULL,
    .socket = NULL,
    .port = 3306,
    .pool_size = 10
};
static ConnectionPool connection_pool;

// Initialize database connection pool
int db_init(void) {

    get_config_section("database", config_callback, &cfg);

    if(!cfg.host || !cfg.user || !cfg.password || !cfg.name) {
        fprintf(stderr, "Database configuration is incomplete\n");
        return EXIT_FAILURE;
    }

    pthread_mutex_init(&connection_pool.lock, NULL);
    connection_pool.count = 0;
    connection_pool.max = cfg.pool_size;

    for (int i = 0; i < connection_pool.max; i++) {
        MYSQL *conn = mysql_init(NULL);
        if (!conn) {
            fprintf(stderr, "Failed to initialize MySQL connection\n");
            exit(EXIT_FAILURE);
        }

        // Set connection options
        mysql_options(conn, MYSQL_SET_CHARSET_NAME, "utf8mb4");
        mysql_options(conn, MYSQL_INIT_COMMAND, "SET NAMES utf8mb4");

        // Connect to database
        if (!mysql_real_connect(conn, cfg.host, cfg.user, cfg.password, cfg.name, cfg.port, cfg.socket, 0)) {
            fprintf(stderr, "Failed to connect to database: %s\n", mysql_error(conn));
            mysql_close(conn);
            return EXIT_FAILURE;
        }

        connection_pool.connections[connection_pool.count++] = conn;
    }

    printf("Database pool initialized with %d connections\n", connection_pool.count);
    return EXIT_SUCCESS;
}

// Get connection from pool
MYSQL *db_get_connection(void) {

    pthread_mutex_lock(&connection_pool.lock);

    if (connection_pool.count == 0) {
        // Create new connection if pool is empty
        MYSQL *conn = mysql_init(NULL);
        if (conn && mysql_real_connect(conn, cfg.host, cfg.user, cfg.password, cfg.name, cfg.port, NULL, 0)) {
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

// Execute query without result
bool db_execute_query(MYSQL *conn, const char *query) {
    struct timespec _db_q_start, _db_q_end;
    clock_gettime(CLOCK_MONOTONIC, &_db_q_start);
    int _rc = mysql_query(conn, query);
    clock_gettime(CLOCK_MONOTONIC, &_db_q_end);

    uint64_t _db_ms = (uint64_t)((_db_q_end.tv_sec - _db_q_start.tv_sec) * 1000 + (_db_q_end.tv_nsec - _db_q_start.tv_nsec) / 1000000);
    metrics_record_mysql_query_ms(_db_ms);

    if (_rc != 0) {
        fprintf(stderr, "Query failed: %s\n", mysql_error(conn));
        return false;
    }
    return true;
}

// Execute query and return result
MYSQL_RES *db_execute_query_result(MYSQL *conn, const char *query) {
    struct timespec _db_q_start, _db_q_end;
    clock_gettime(CLOCK_MONOTONIC, &_db_q_start);
    int _rc = mysql_query(conn, query);
    clock_gettime(CLOCK_MONOTONIC, &_db_q_end);

    uint64_t _db_ms = (uint64_t)((_db_q_end.tv_sec - _db_q_start.tv_sec) * 1000 + (_db_q_end.tv_nsec - _db_q_start.tv_nsec) / 1000000);
    metrics_record_mysql_query_ms(_db_ms);

    if (_rc != 0) {
        fprintf(stderr, "Query failed: %s\n", mysql_error(conn));
        return NULL;
    }
    return mysql_store_result(conn);
}

// Free result
void db_free_result(MYSQL_RES *result) {
    if (result)
        mysql_free_result(result);
}