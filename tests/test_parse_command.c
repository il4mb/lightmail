#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "imap.h"

int main(void) {
    char tag[128];
    char command[128];
    char args[512];

    char buf[] = "A001 LOGIN \"user\" \"pass\"\r\n";
    int ok = parse_command(buf, tag, command, args);
    assert(ok);
    if (strcmp(tag, "A001") != 0) return 2;
    if (strcasecmp(command, "LOGIN") != 0) return 3;
    if (strstr(args, "user") == NULL) return 4;

    printf("test_parse_command: OK\n");
    return 0;
}
