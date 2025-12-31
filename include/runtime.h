#ifndef RUNTIME_H
#define RUNTIME_H

#include <mysql/mysql.h>

typedef struct {
    MYSQL *mysql;
    int shutting_down;
} Runtime;

extern Runtime g_runtime;

int runtime_init(void);
void runtime_shutdown(void);

#endif
