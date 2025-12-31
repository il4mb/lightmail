#ifndef SHUTDOWN_H
#define SHUTDOWN_H

#include <signal.h>

extern volatile sig_atomic_t g_shutdown;
void setup_signal_handlers(void);

#endif
