#ifndef LIGHTMAIL_LOCK_H
#define LIGHTMAIL_LOCK_H

#define PID_FILE_PATH "/var/run/lightmail/lightmail.pid"

int acquire_lock(const char *pidfile);
void release_lock(void);
int is_already_running();

#endif // LIGHTMAIL_LOCK_H