#include "s3.h"
#include <string.h>
#include <stdio.h>

int main(void) {
    char *key = s3_generate_key(1, 2, 3);
    if (!key) return 2;
    if (strstr(key, "accounts/1/mailboxes/2/messages/3.eml") == NULL) { free(key); return 3; }
    free(key);
    printf("test_s3: OK\n");
    return 0;
}