#include "pop3.h"
#include "log.h"
#include "conf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void start_pop3(void) {
    /* Placeholder POP3 server - in future implement RFC1939 server */
    LOGI_S("pop3", "POP3 service placeholder started");
}

/* Simple instrumented POP3 command examples */
void pop3_user_login(const char *user) {
    LOGI_S("pop3", "USER login attempt user=%s", user);
}

void pop3_user_login_failed(const char *user) {
    LOGW_S("pop3", "USER login failed user=%s", user);
}
