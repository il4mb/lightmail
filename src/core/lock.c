#include "lock.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int lock_fd = -1;

int acquire_lock(const char *pidfile) {
    lock_fd = open(pidfile, O_RDWR | O_CREAT, 0644);
    if (lock_fd < 0) {
        perror("open pidfile");
        return 0;
    }

    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0};

    if (fcntl(lock_fd, F_SETLK, &fl) < 0) {
        if (errno == EACCES || errno == EAGAIN) {
            fprintf(stderr, "Instance already running\n");
        } else {
            perror("fcntl");
        }
        close(lock_fd);
        return 0;
    }

    // Write PID
    ftruncate(lock_fd, 0);
    char buf[32];
    snprintf(buf, sizeof(buf), "%d\n", getpid());
    write(lock_fd, buf, strlen(buf));

    return 1;
}

void release_lock(void) {
    if (lock_fd >= 0) {
        close(lock_fd); // releases lock automatically
        lock_fd = -1;
    }
}
