#ifndef RUNTIME_H
#define RUNTIME_H

#include <mysql/mysql.h>

typedef struct {
    MYSQL *mysql;
    int is_running;
} Runtime;

extern Runtime g_runtime;

int runtime_init(void);
void runtime_shutdown(void);

#endif
