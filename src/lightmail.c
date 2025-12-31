#include "lightmail.h"
#include "conf.h"
#include "log.h"
#include "parser.h"
#include "shutdown.h"
#include <dlfcn.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Command line options structure
typedef struct {
    char config_file[256];
    int reload;
    int help;
    int version;
} CommandOptions;

void args_callback(const char *k, const char *v, void *ctx) {
    CommandOptions *s = (CommandOptions *)ctx;
    // Safety check: k should always exist, but let's be sure
    if (!k || strlen(k) < 2)
        return;

    switch (k[1]) {
    case 'c':
        if (v) { // Always check if v is NULL (user forgot the filename)
            strncpy(s->config_file, v, sizeof(s->config_file) - 1);
            s->config_file[sizeof(s->config_file) - 1] = '\0';
        } else {
            fprintf(stderr, "Error: Option -c requires a configuration file path.\n");
        }
        break;
    case 'h':
        s->help = 1;
        break;
    case 'V':
        s->version = 1;
        break;
    case 'reload':
        s->reload = 1;
        break;
    default:
        printf("Unknown option: %s\n", k);
        break;
    }
}

// Print usage information
void print_usage(const char *progname) {
    printf("LightMail IMAP Server v1.0\n");
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("\n");
    printf("Options:\n");
    printf("  -c FILE    Use specified configuration file\n");
    printf("  -d         Run as daemon (background process)\n");
    printf("  -v         Verbose output\n");
    printf("  -t         Test configuration and exit\n");
    printf("  -h         Show this help message\n");
    printf("  -V         Show version information\n");
    printf("\n");
    printf("Configuration search order:\n");
    printf("  1. -c option specified file\n");
    printf("  2. ./lightmail.conf\n");
    printf("  3. $EXE_DIR/lightmail.conf\n");
    printf("  4. $EXE_DIR/../config/lightmail.conf\n");
    printf("  5. /etc/lightmail/lightmail.conf\n");
    printf("  6. /usr/local/etc/lightmail/lightmail.conf\n");
    printf("  7. /opt/lightmail/etc/lightmail.conf\n");
    printf("\n");
    printf("Environment variables:\n");
    printf("  LIGHTMAIL_RUNTIME_DIR  Runtime data directory (default: /var/lib/lightmail)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -c ./myconfig.conf    # Use custom config\n", progname);
    printf("  %s -d                    # Run as daemon\n", progname);
    printf("  %s -t                    # Test configuration\n", progname);
}

// Print version information
void print_version() {
    printf("LightMail IMAP Server v1.0\n");
    printf("Built on %s %s\n", __DATE__, __TIME__);
    printf("Copyright (c) 2024 LightMail Project\n");
    printf("License: MIT\n");
}

int main(int argc, char *argv[]) {
    CommandOptions opts = {0};
    parse_command_line(argc, argv, args_callback, &opts);

    if (is_already_running()) {
        fprintf(stderr, "LightMail is already running\n");
        return EXIT_FAILURE;
    }

    if (init_config(opts.config_file) == EXIT_FAILURE) {
        return EXIT_FAILURE;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return EXIT_FAILURE;
    }

    if (pid > 0) {
        // Parent exits immediately
        printf("LightMail started (PID %d)\n", pid);
        return EXIT_SUCCESS;
    }

    // ---- CHILD (DAEMON) ----
    umask(0);

    if (setsid() < 0) {
        _exit(1);
    }

    chdir("/");

    int fd = open("/dev/null", O_RDWR);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > 2)
        close(fd);

    // Now safe to initialize logging & signals
    setup_signal_handlers();
    LOG_INIT();

    start_imap();

    // Graceful shutdown
    free_config();
    LOG_CLOSE();
    _exit(0);
}
