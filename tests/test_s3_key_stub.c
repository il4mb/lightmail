#include <stdio.h>
#include <stdlib.h>

char *s3_generate_key(int account_id, int mailbox_id, int message_id) {
    char *buf = NULL;
    if (asprintf(&buf, "accounts/%d/mailboxes/%d/messages/%d.eml", account_id, mailbox_id, message_id) < 0) return NULL;
    return buf;
}
