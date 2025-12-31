// shutdown.c
#include "shutdown.h"
#include <unistd.h>

volatile sig_atomic_t g_shutdown = 0;

static void handle_sigterm(int sig) {
    (void)sig;
    g_shutdown = 1;
}

void setup_signal_handlers(void) {
    struct sigaction sa = {0};
    sa.sa_handler = handle_sigterm;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
}
