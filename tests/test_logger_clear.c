#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/log.h"
#include "../include/conf.h"

int main(void) {
    char tmpfile[] = "/tmp/lightmail_logtest_clear_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    close(fd);

    if (log_init(tmpfile, LOG_OUTPUT_FILE) != 0) {
        fprintf(stderr, "log_init failed\n");
        unlink(tmpfile);
        return 1;
    }

    /* Write an initial message that should be cleared on reload */
    log_emit(LOG_LEVEL_INFO, "imap", "alice@example.com", "sess1", "PERSISTENT before reload");

    /* Now enable clear_on_reload and reload */
    set_config_value("logging", "clear_on_reload", "1");
    log_reload_config();

    /* Emit a message after reload which should be the only message present */
    log_emit(LOG_LEVEL_INFO, "imap", "alice@example.com", "sess1", "POST-RELOAD message");

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

    /* The pre-reload message must not be present */
    if (strstr(buf, "PERSISTENT before reload") != NULL) {
        fprintf(stderr, "pre-reload message still present\n");
        unlink(tmpfile);
        return 1;
    }

    /* The post-reload message must be present */
    if (strstr(buf, "POST-RELOAD message") == NULL) {
        fprintf(stderr, "post-reload message not found\n");
        unlink(tmpfile);
        return 1;
    }

    unlink(tmpfile);
    printf("OK\n");
    return 0;
}
