#ifndef LIGHTMAIL_H
#define LIGHTMAIL_H
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#define PID_FILE "/tmp/lightmail.pid"

static int is_already_running() {
    int fd = open(PID_FILE, O_RDWR | O_CREAT, 0666);
    if (fd < 0)
        return 1; // Error opening

    // Try to place an exclusive lock on the file
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        close(fd);
        return 1; // File is locked, instance already running
    }

    // Success: Write PID to file for reference
    char buf[16];
    snprintf(buf, sizeof(buf), "%d\n", getpid());
    ftruncate(fd, 0);
    write(fd, buf, strlen(buf));
    // Note: Do not close(fd) yet, or you release the lock!
    return 0;
}
#endif /* LIGHTMAIL_H */