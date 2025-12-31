// shutdown.c
#include "shutdown.h"
#include <unistd.h>

volatile sig_atomic_t g_shutdown = 0;
volatile sig_atomic_t g_reload = 0;

static void handle_sigterm(int sig) {
    (void)sig;
    g_shutdown = 1;
}

static void handle_sighup(int sig) {
    (void)sig;
    g_reload = 1;
}

int is_reload_requested(void) {
    return g_reload != 0;
}

void clear_reload_request(void) {
    g_reload = 0;
}

void setup_signal_handlers(void) {
    struct sigaction sa = {0};
    sa.sa_handler = handle_sigterm;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    struct sigaction sh = {0};
    sh.sa_handler = handle_sighup;
    sigemptyset(&sh.sa_mask);
    sh.sa_flags = 0;
    sigaction(SIGHUP, &sh, NULL);
}
