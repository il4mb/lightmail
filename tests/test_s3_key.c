#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "s3.h"

int main(void) {
    char *key = s3_generate_key(1, 2, 3);
    if (!key) return 2;
    if (strstr(key, "accounts/1/mailboxes/2/messages/3.eml") == NULL) return 3;
    free(key);
    printf("test_s3_key: OK\n");
    return 0;
}
