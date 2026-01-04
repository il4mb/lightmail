#include "runtime.h"
#include <stdio.h>
#include <stdlib.h>

Runtime g_runtime = {0};

int runtime_init(void) {
    g_runtime.mysql = mysql_init(NULL);
    if (!g_runtime.mysql) {
        fprintf(stderr, "mysql_init failed\n");
        return 0;
    }

    printf("Runtime initialized\n");
    return 1;
}

void runtime_shutdown(void) {
    if (g_runtime.mysql) {
        mysql_close(g_runtime.mysql);
        g_runtime.mysql = NULL;
    }

    printf("Runtime cleaned up\n");
}
