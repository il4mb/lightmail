#include "pop3.h"
#include "log.h"
#include <lightmail.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void pop3_start(void) {
    /* Placeholder POP3 server - in future implement RFC1939 server */
    LOGI("pop3", "POP3 service placeholder started");
}

/* Simple instrumented POP3 command examples */
void pop3_user_login(const char *user) {
    LOGI("pop3", "USER login attempt user=%s", user);
}

void pop3_user_login_failed(const char *user) {
    LOGW("pop3", "USER login failed user=%s", user);
}
