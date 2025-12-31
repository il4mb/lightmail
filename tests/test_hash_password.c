#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "auth.h"

int main(void) {
    char out1[65];
    char out2[65];
    hash_password("password", out1);
    hash_password("password", out2);
    assert(strcmp(out1, out2) == 0);
    if (strlen(out1) != 64) return 2;
    printf("test_hash_password: OK\n");
    return 0;
}
