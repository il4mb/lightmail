#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/log.h"
#include "../include/conf.h"

int main(void) {
    char tmpfile[] = "/tmp/lightmail_logtest_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    close(fd);

    if (log_init(tmpfile) != 0) {
        fprintf(stderr, "log_init failed\n");
        unlink(tmpfile);
        return 1;
    }

    log_emit(LOG_LEVEL_INFO, "imap", "alice@example.com", "sess1", "APPEND completed for mailbox %s size %d", "INBOX", 123);
    log_emit(LOG_LEVEL_DEBUG, "imap", "alice@example.com", "sess1", "This is a debug message: %d", 42);

    /* Now set logging level via config and reload */
    set_config_value("logging", "level", "DEBUG");
    set_config_value("logging", "imap_level", "DEBUG");
    log_reload_config();

    /* Emit a debug message which should now be recorded */
    log_emit(LOG_LEVEL_DEBUG, "imap", "alice@example.com", "sess1", "Post-reload debug: %d", 7);

    /* give flusher some time to write */
    usleep(200 * 1000);
    log_close();

    FILE *f = fopen(tmpfile, "r");
    if (!f) {
        perror("fopen");
        unlink(tmpfile);
        return 1;
    }
    char buf[4096];
    size_t got = fread(buf, 1, sizeof(buf)-1, f);
    buf[got] = '\0';
    fclose(f);

    /* basic checks: contain APPEND and service imap and user */
    if (strstr(buf, "APPEND completed") == NULL) {
        fprintf(stderr, "APPEND message not found in log\n");
        unlink(tmpfile);
        return 1;
    }
    if (strstr(buf, "\"service\":\"imap\"") == NULL) {
        fprintf(stderr, "service field missing\n");
        unlink(tmpfile);
        return 1;
    }
    if (strstr(buf, "alice@example.com") == NULL) {
        fprintf(stderr, "user field missing\n");
        unlink(tmpfile);
        return 1;
    }

    unlink(tmpfile);
    printf("OK\n");
    return 0;
}
