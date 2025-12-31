#ifndef SHUTDOWN_H
#define SHUTDOWN_H

#include <signal.h>

extern volatile sig_atomic_t g_shutdown;

/* Reload request (SIGHUP) helpers */
int is_reload_requested(void);
void clear_reload_request(void);

void setup_signal_handlers(void);

#endif
